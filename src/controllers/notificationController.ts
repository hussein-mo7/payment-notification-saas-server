import { createHash } from 'crypto';
import { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import { User, PaymentNotification, Notification } from '../models';
import { AuthRequest } from '../types';
import { BadRequestError } from '../utils/errors';

export const createPaymentNotification = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { source, title, message, receivedAt, amount, currency, transactionId } = req.body;
    if (!source || !title || !message) {
      next(new BadRequestError('source, title and message are required'));
      return;
    }
    const messageStored = _stripTrailingAvailableBalanceLine(_normalizeDigits(String(message)));
    const combinedForCard = _normalizeDigits(`${String(title ?? '')}\n${messageStored}`).toLowerCase();
    
    // Check for promotional messages from wallet providers (not actual payment notifications).
    if (_isPromotionalMessageFromPaymentProvider(combinedForCard)) {
      res.status(200).json({ success: false, reason: 'Promotional message from payment provider' });
      return;
    }
    
    // Check for outgoing/service purchases (not incoming payments).
    if (_isOutgoingOrServicePurchase(combinedForCard)) {
      res.status(200).json({ success: false, reason: 'Outgoing transaction or service purchase' });
      return;
    }
    
    // Check for manual transfer instructions via WhatsApp (not automatic payment notifications).
    if (_isWhatsAppManualTransferInstruction(combinedForCard)) {
      res.status(200).json({ success: false, reason: 'Manual WhatsApp transfer instruction' });
      return;
    }
    
    if (_isCardSpendExcluded(combinedForCard)) {
      res.status(200).json({ success: false, reason: 'Card spend excluded' });
      return;
    }
    let parsedAmount: number | null = null;
    if (amount !== undefined && amount !== null && amount !== '') {
      const n = Number(amount);
      if (Number.isFinite(n) && n > 0) parsedAmount = n;
    }

    const received = receivedAt ? new Date(receivedAt) : new Date();
    const user = await User.findById(req.userId).select('_id').lean();
    if (!user) {
      res.status(201).json({ success: true, data: null });
      return;
    }

    const txId = transactionId ? String(transactionId).trim().toLowerCase() : '';
    if (txId) {
      const existing = await PaymentNotification.findOne({ userId: req.userId, transactionId: txId });
      if (existing) {
        res.status(201).json({ success: true, data: existing });
        return;
      }
    }

    const contentHash = _computePaymentContentHash({
      userId: String(req.userId),
      source: String(source),
      message: messageStored,
      amount: parsedAmount,
      transactionId: txId || undefined,
      receivedAt: received,
    });
    const existingByContent = await PaymentNotification.findOne({
      userId: req.userId,
      contentHash,
    });
    if (existingByContent) {
      res.status(201).json({ success: true, data: existingByContent });
      return;
    }

    const dir = 'detected' as const;

    const doc = await PaymentNotification.create({
      userId: req.userId,
      source,
      title,
      message: messageStored,
      direction: dir,
      ...(parsedAmount != null ? { amount: parsedAmount } : {}),
      currency,
      transactionId: txId ? txId : undefined,
      contentHash,
      receivedAt: received,
    });

    res.status(201).json({ success: true, data: doc });
    return;
  } catch (e) {
    next(e);
  }
};

/**
 * Amount token: greedy integer (\d+) so "1200.00" is not split as "120" + "0.00".
 * Thousands: 1,234.56 via \d{1,3}(?:[,\s]\d{3})+ optional chain before decimals.
 */
const _amountToken = String.raw`(?:(?:\d{1,3}(?:[,\s]\d{3})+|\d+)(?:[.,]\d{1,2})?)`;
const _amountRegex = new RegExp(
  String.raw`(?<!\d)(${_amountToken})\s*(USD|US\$|ILS|NIS|JOD|JDS|\$|₪|شيكل|شيقل|دولار)?`,
  'i'
);
const _amountAfterMablagRegex = new RegExp(String.raw`مبلغ[\s:]*(${_amountToken})`, 'i');
/** BOP / mobile banking: "بمبلغ 55.00 ILS" — try before global _amountRegex (avoids 120 vs 1200). */
const _amountAfterBimablagRegex = new RegExp(
  String.raw`بمبلغ[\s:]*(${_amountToken})\s*(USD|US\$|ILS|NIS|JOD|JDS|\$|₪|شيكل|شيقل|دولار)?`,
  'i'
);
const _transactionIdRegex = new RegExp(
  String.raw`(?:tx(?:n)?|transaction|ref|reference|رقم العملية|رقم المرجع)[\s:#-]*([A-Za-z0-9\-]{4,})`,
  'i'
);
const _senderRegex = new RegExp(
  String.raw`(?:from|sender|from account|مرسل|من)[\s:]*([A-Za-z0-9 _\-]{3,30})`,
  'i'
);

function _containsAny(input: string, terms: string[]): boolean {
  const lower = input.toLowerCase();
  for (const t of terms) {
    if (lower.includes(t.toLowerCase())) return true;
  }
  return false;
}

/** Only internal moves between the user's own accounts — not "new" money from outside. */
function _isInternalAccountTransferOnly(combinedLower: string): boolean {
  const t = combinedLower;
  if (t.includes('بين الحسابات') || t.includes('between accounts')) return true;
  if (t.includes('تحويل بنكي بين الحسابات') || t.includes('تحويل بين الحسابات')) return true;
  return false;
}

/**
 * Card spend at POS / merchant — not account transfers (حركة على بطاقة, التاجر, رقم البطاقة).
 * e.g. "تم استلام حركتك من قبل التاجر بنجاح … مبلغ الحركة … رقم البطاقة … بنك فلسطين"
 */
function _isCardSpendExcluded(combinedLower: string): boolean {
  const t = combinedLower;
  if (t.includes('حركة على بطاقة')) return true;
  if (t.includes('تم استلام حركتك من قبل التاجر')) return true;
  if (t.includes('من قبل التاجر') && (t.includes('رقم البطاقة') || t.includes('البطاقة:'))) return true;
  if (t.includes('مبلغ الحركة') && t.includes('رقم البطاقة')) return true;
  return false;
}

/**
 * Promotional/marketing messages from payment providers (not actual payment notifications).
 * e.g. "وفّرنا عليك أكتر! حوّل أجرة التكسي باستخدام Jawwal Pay بدون أي رسوم..."
 * Characteristics: marketing links, promotional language, no transaction details.
 */
function _isPromotionalMessageFromPaymentProvider(combinedLower: string): boolean {
  const t = combinedLower;
  
  // Marketing/promotional Jawwal messages
  if (t.includes('وفّرنا عليك')) return true;
  if (t.includes('حوّل أجرة') && t.includes('بدون أي رسوم')) return true;
  if (t.includes('للمزيد') && t.includes('http')) return true;
  if (t.includes('لاستخدام التطبيق') && (t.includes('http') || t.includes('onelink'))) return true;
  
  // Generic promotional markers from any wallet
  const hasPromotionalLanguage = t.includes('عرض') || t.includes('اشتراك') || t.includes('ترويج') || 
                                  t.includes('promotion') || t.includes('offer') || t.includes('campaign');
  const hasMarketingLinks = /http[s]?:\/\//.test(t) && 
                             (t.includes('onelink') || t.includes('qlink') || t.includes('bit.ly') || 
                              t.includes('tinyurl') || t.includes('short.link'));
  
  if (hasPromotionalLanguage && hasMarketingLinks) return true;
  
  // Message is just advertising/call-to-action with no amount/transaction data
  if (!_containsAny(t, ['مبلغ', 'بمبلغ', 'amount', 'received', 'credited', 'تم', 'استلم', 
                        'transferred', 'paid', 'sent', 'تحويل', 'دفع', 'ايداع', 'إيداع'])) {
    if (hasMarketingLinks || t.includes('download') || t.includes('تحميل') || 
        t.includes('تطبيق') || t.includes('app')) {
      return true;
    }
  }
  
  return false;
}

/**
 * Outgoing transactions or service purchases (not incoming payments).
 * e.g. "تمت عملية شراء حزمة جوال بنجاح" (mobile package purchase)
 * e.g. "تم شراء رصيد" (credit purchase)
 */
function _isOutgoingOrServicePurchase(combinedLower: string): boolean {
  const t = combinedLower;
  // Service/package purchases
  if (t.includes('عملية شراء') || t.includes('شراء حزمة') || t.includes('شراء رصيد')) return true;
  if (t.includes('شراء') && (t.includes('جوال') || t.includes('باقة') || t.includes('رصيد'))) return true;
  if (t.includes('تم شراء')) return true;
  if (t.includes('تم دفع رسوم') || t.includes('رسوم خدمة')) return true;
  return false;
}

/**
 * Manual transfer instructions via WhatsApp/messaging (not automatic payment notifications).
 * e.g. "ابعت الاشعار على الوتس على الرقم هادا… المبلغ 7000شيكل"
 * (Send notification on WhatsApp to this number… Amount 7000 shekels)
 */
function _isWhatsAppManualTransferInstruction(combinedLower: string): boolean {
  const t = combinedLower;
  // Manual instructions to send money via WhatsApp
  if (t.includes('ابعت') && t.includes('وتس')) return true;
  if (t.includes('ابعت') && t.includes('واتس')) return true;
  if (t.includes('بعت على الوتس')) return true;
  if (t.includes('بعت على واتس')) return true;
  if (t.includes('رقم الوتس') || t.includes('رقم واتس')) return true;
  // Generic "send notification" instructions
  if (t.includes('ابعت الاشعار') || t.includes('بعت الاشعار')) return true;
  return false;
}

/** Remove available-balance clause from SMS (keep transfer line only). Not anchored to EOF — OEMs append \\n + ⁨BOP⁩ after the amount. */
function _stripTrailingAvailableBalanceLine(input: string): string {
  if (!input) return input;
  let s = input.replace(/\r\n/g, '\n').trim();
  
  // Remove رصيد (balance) lines in various forms:
  // - "رصيدكم المتوفر" / "رصيد المتوفر" (your available balance)
  // - "الرصيد الحالي" (current balance)
  // - "الرصيد:" (balance:)
  s = s.replace(/[\s.،\n]*رصيد(?:كم|ك)?\s+المتوفر(?:\s+هو)?\s*[\d.,]+/gu, '');
  s = s.replace(/[\s.،\n]*الرصيد\s+الحالي\s*:?\s*[\d.,ILSNISJODilsnisjod\s$₪]+/gu, '');
  s = s.replace(/[\s.،\n]*الرصيد\s*:?\s*[\d.,ILSNISJODilsnisjod\s$₪]+/gu, '');
  
  const lines = s
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => {
      if (line.length === 0) return false;
      const noMarks = line.replace(/[\u200c-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '').trim();
      return !/^BOP$/i.test(noMarks);
    });
  s = lines.join('\n').trim();
  return s.replace(/[.،\s]+$/u, '').trim();
}

/** Casual chat / WhatsApp meta-messages wrongly classified as payments (e.g. Jawwal tray). */
function _isCasualWhatsAppOrChatJunk(lower: string): boolean {
  if (lower.includes('whatsapp') || lower.includes('واتس')) return true;
  if (lower.includes('ع الواتس') || lower.includes('عالواتس')) return true;
  if (lower.includes('بعتلك الاشعار') || lower.includes('بعتلك الإشعار')) return true;
  if (lower.includes('بعتلك') && (lower.includes('اشعار') || lower.includes('إشعار'))) return true;
  return false;
}

function _normalizeForFingerprint(message: string): string {
  return _normalizeDigits(message).replace(/\s+/g, ' ').trim();
}

function _computePaymentContentHash(params: {
  userId: string;
  source: string;
  message: string;
  amount: number | null | undefined;
  transactionId?: string;
  /** Disambiguates two identical-looking transfers in the same minute (Issue 3). */
  receivedAt: Date;
}): string {
  const tx = (params.transactionId || '').trim().toLowerCase();
  if (tx) return `tx:${tx}`;
  const norm = _normalizeForFingerprint(params.message);
  const minuteBucket = Math.floor(params.receivedAt.getTime() / 60000);
  const amt =
    params.amount != null && Number.isFinite(params.amount) && params.amount > 0
      ? String(params.amount)
      : 'na';
  return createHash('sha256')
    .update(`${params.userId}|${params.source}|${norm}|${amt}|${minuteBucket}`, 'utf8')
    .digest('hex');
}

function _normalizeDigits(input: string): string {
  const arabicIndic = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'];
  const easternArabicIndic = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
  let out = input;
  for (let i = 0; i < 10; i++) {
    out = out.split(arabicIndic[i]).join(String(i));
    out = out.split(easternArabicIndic[i]).join(String(i));
  }
  return out;
}

function _parseAmount(raw?: string): number | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let normalized = trimmed.split(' ').join('');

  if (normalized.includes(',') && normalized.includes('.')) {
    if (normalized.lastIndexOf(',') > normalized.lastIndexOf('.')) {
      normalized = normalized.split('.').join('').split(',').join('.');
    } else {
      normalized = normalized.split(',').join('');
    }
  } else if (normalized.includes(',')) {
    const parts = normalized.split(',');
    if (parts.length > 2) {
      normalized = normalized.split(',').join('');
    } else {
      const decimalPart = parts[parts.length - 1];
      normalized =
        decimalPart.length <= 2 ? normalized.split(',').join('.') : normalized.split(',').join('');
    }
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function _detectSource(packageNameLower: string, titleLower: string, messageLower: string, input: string): string | null {
  // Direct app detection
  if (_containsAny(input, ['palpay', 'pal pay', 'بال باي', 'بالباي'])) return 'PalPay';
  if (_containsAny(input, ['jawwal', 'jawwalpay', 'jawwal pay', 'جوال باي', 'جوال'])) return 'Jawwal Pay';
  if (
    _containsAny(input, [
      'palestine bank',
      'bank of palestine',
      'bop',
      'بنك فلسطين',
      'تحويل بنكي',
      'تحويل لصديق',
      'bankofpalestine',
    ])
  ) {
    return 'Palestine Bank';
  }

  const isSmsApp = _containsAny(packageNameLower, [
    'com.google.android.apps.messaging',
    'com.samsung.android.messaging',
    'com.android.mms',
    'com.android.messaging',
    'com.miui.mms',
    'com.huawei.message',
    'com.oneplus.mms',
    'com.coloros.mms',
  ]);

  // Check for Iburaq transfer via SMS
  if (isSmsApp && _containsAny(input, ['iburaq', 'ايبرق', 'البراق'])) {
    return 'Iburaq';
  }

  // Check for bank/payment SMS
  const hasBankHint = _containsAny(`${titleLower} ${messageLower}`, [
    'bank',
    'bop',
    'palestine bank',
    'bank of palestine',
    'bankofpalestine',
    'palpay',
    'jawwal',
    'بنك',
    'فلسطين',
    'مبلغ',
    'حساب',
    'حسابك',
    'رصيد',
    'تحويل',
    'تحويل بنكي',
    'تحويل لصديق',
    'دفعة',
    'ايداع',
    'إيداع',
    'استلام',
    'استقبال',
    'حوالة',
    'استلام',
    'عملية',
    'إشعار',
    'received',
    'credited',
    'deposit',
  ]);

  if (isSmsApp && hasBankHint) return 'SMS Payment';
  return null;
}

function _isFalsePositive(input: string): boolean {
  const lower = input.toLowerCase();
  if (_isOtpOrStepUpVerificationMessage(lower)) return true;
  return _containsAny(lower, [
    'otp',
    'one-time password',
    'verification code',
    'verify',
    'confirm code',
    'activation code',
    'security code',
    'password reset',
    'login code',
    'رمز التحقق',
    'رمز التأكيد',
    'code:',
    'code :',
    'two-factor',
    'authenticator',
    'signed in from',
    'new device',
    'كلمة السر المؤقتة',
    'كلمه السر المؤقتة',
    'السر المؤقتة',
    'يرجى استخدام كلمة السر',
    'استخدم كلمة السر',
    'temporary password',
    'temp password',
    'one time password',
  ]);
}

/** Bank step-up SMS — e.g. temporary password to complete transaction; not a payment alert. */
function _isOtpOrStepUpVerificationMessage(lower: string): boolean {
  if (lower.includes('كلمة السر المؤقتة') || lower.includes('كلمه السر المؤقتة')) return true;
  if (lower.includes('يرجى استخدام كلمة السر') || lower.includes('استخدم كلمة السر المؤقتة')) return true;
  if (
    lower.includes('لاستكمال الحركة') &&
    (lower.includes('مؤقت') || lower.includes('code') || lower.includes('رمز'))
  ) {
    return true;
  }
  if (
    /code\s*:\s*\d/i.test(lower) &&
    (lower.includes('مؤقت') || lower.includes('استكمال') || lower.includes('يرجى'))
  ) {
    return true;
  }
  return false;
}

/** Non-bank notifications that often contain digits (games, social, weather). */
/** e.g. "موبايل: تحويل بنكي: … بمبلغ 55.00 ILS" — bank app may use OEM-specific package id. */
function _isPalestineBankTransferLine(fullTextLower: string): boolean {
  return (
    fullTextLower.includes('تحويل بنكي') &&
    (fullTextLower.includes('بمبلغ') || fullTextLower.includes('مبلغ'))
  );
}

/** BOP "Pay to friend" / تحويل دفع — wording omits "تحويل بنكي" (see tray template). */
function _isPalestineBankFriendPaymentLine(fullTextLower: string): boolean {
  const t = fullTextLower;
  const friend =
    t.includes('تحويل دفع') || t.includes('الدفع لصديق') || t.includes('دفع لصديق');
  const money =
    t.includes('بمبلغ') ||
    t.includes('مبلغ') ||
    t.includes('ils') ||
    t.includes('nis') ||
    t.includes('₪');
  return friend && money;
}

/**
 * Incoming money to BOP account / wallet (e.g. شحن محفظة, حوالة واردة, إيداع من جوال باي).
 * Outgoing uses different wording; this path catches receive-side tray text that misses other gates.
 */
function _isPalestineBankIncomingAccountLine(fullTextLower: string): boolean {
  const t = fullTextLower;
  if (!/\d/.test(t)) return false;
  const incomingCue =
    t.includes('حوالة واردة') ||
    t.includes('واردة لحسابك') ||
    t.includes('واردة إلى حسابك') ||
    t.includes('واردة الى حسابك') ||
    t.includes('إيداع') ||
    t.includes('ايداع') ||
    t.includes('استلام') ||
    t.includes('استقبال') ||
    t.includes('من جوال') ||
    t.includes('jawwal pay') ||
    t.includes('جوال باي') ||
    t.includes('credited') ||
    t.includes('deposited') ||
    t.includes('has been credited') ||
    t.includes('has been accepted') ||
    t.includes('تم إضافة') ||
    t.includes('تم اضافة') ||
    t.includes('قيد إيداع') ||
    t.includes('اضافة مبلغ') ||
    t.includes('رصيدكم') ||
    t.includes('المتوفر') ||
    t.includes('iburaq') ||
    t.includes('ايبرق') ||
    t.includes('البراق');
  const bankOrMoney =
    t.includes('bop') ||
    t.includes('بنك') ||
    t.includes('bank') ||
    t.includes('فلسطين') ||
    t.includes('palestine') ||
    t.includes('ils') ||
    t.includes('nis') ||
    t.includes('₪') ||
    t.includes('مبلغ') ||
    t.includes('بمبلغ') ||
    t.includes('بقيمة') ||
    t.includes('شيكل') ||
    t.includes('شيقل') ||
    t.includes('رصيد');
  return incomingCue && bankOrMoney;
}

/** Iburaq SMS tray: often no "bank"/"jawwal" in body — only حوالة واردة + مبلغ/شيكل/رصيد. */
function _isSmsIburaqIncomingWireLine(fullTextLower: string): boolean {
  const t = fullTextLower;
  if (!/\d/.test(t)) return false;
  const wire =
    t.includes('حوالة واردة') ||
    t.includes('واردة لحسابك') ||
    t.includes('واردة إلى حسابك') ||
    t.includes('واردة الى حسابك');
  const money =
    t.includes('بمبلغ') ||
    t.includes('مبلغ') ||
    t.includes('شيكل') ||
    t.includes('شيقل') ||
    t.includes('رصيد') ||
    t.includes('رصيدكم') ||
    t.includes('المتوفر');
  return wire && money;
}

function _isLikelyNonPaymentJunk(input: string): boolean {
  const lower = input.toLowerCase();
  if (_isCasualWhatsAppOrChatJunk(lower)) return true;
  return _containsAny(lower, [
    'steps',
    'calories',
    'followers',
    'likes',
    'views',
    'score',
    'level ',
    'weather',
    'youtube',
    'tiktok',
    'instagram',
    'delivery',
    'tracking',
    'promo code',
    'خصم',
    'عرض',
    'طقس',
    'متابع',
    'لعبة',
    'نقاط',
  ]);
}

function _isKnownPaymentAppPackage(packageLower: string): boolean {
  return _containsAny(packageLower, [
    'palpay',
    'com.palpay',
    'net.palpay',
    'ps.palpay',
    'jawwal',
    'jawwalpay',
    'ps.jawwal',
    'com.jawwal',
    'bankofpalestine',
    'bop',
    'com.bop',
    'bop.mobile',
    'bop.ps',
    'ps.bop',
    'albop',
    'efinance',
    'palestinebank',
    'palestine.bank',
    'cash.pal',
    'wallet.ps',
  ]);
}

function _isSmsAppPackage(packageLower: string): boolean {
  if (!packageLower) return false;
  if (
    _containsAny(packageLower, [
      'com.google.android.apps.messaging',
      'com.samsung.android.messaging',
      'com.android.mms',
      'com.android.messaging',
      'miui.mms',
      'huawei.message',
      'oneplus.mms',
      'coloros.mms',
    ])
  ) {
    return true;
  }
  if (packageLower.includes('messaging')) return true;
  if (packageLower.includes('mms')) return true;
  if (packageLower.includes('sms') && packageLower.includes('android')) return true;
  if (packageLower.includes('telephony')) return true;
  return false;
}

/** Strong money cues — aligned with Android [shouldRoughlyLookLikePayment] / SMS+bank path. */
function _hasStrongPaymentSignal(fullTextLower: string): boolean {
  return _containsAny(fullTextLower, [
    'received',
    'credited',
    'deposited',
    'payment received',
    'transfer received',
    'you received',
    'account credited',
    'credit alert',
    'cash in',
    'you sent',
    'you transferred',
    'you paid',
    'sent to',
    'payment to',
    'transfer to',
    'paid to',
    'outgoing transfer',
    'money sent',
    'transaction sent',
    'deducted',
    'debited',
    'withdrawal',
    'cash out',
    'تم استلام',
    'تم ايداع',
    'تم إيداع',
    'استلمت',
    'وصلك',
    'وردت',
    'تم استقبال',
    'حوالة واردة',
    'واردة لحسابك',
    'واردة الى حسابك',
    'واردة إلى حسابك',
    'تم تحويل لك',
    'تم الايداع',
    'تم الإيداع',
    'تمت إضافة',
    'تم اضافه',
    'اضافة الى حسابك',
    'إضافة إلى حسابك',
    'تم اضافة',
    'تم إضافة',
    'إشعار إيداع',
    'اشعار ايداع',
    'تم ارسال',
    'ارسلت',
    'تم الدفع لـ',
    'تم الدفع إلى',
    'تم الدفع ل',
    'دفعت',
    'تم خصم',
    'تم التحويل الى',
    'تم التحويل إلى',
    'حولت',
    'حوالة صادرة',
    'صادرة من حسابك',
    'تم سحب',
    'شراء',
    'تحويل بنكي',
    'تحويل دفع لصديق',
    'عملية ناجحة',
    'إشعار عملية',
    'اشعار عملية',
    'عملية مالية',
    'تم بنجاح',
    'بنجاح',
    'تمت العملية',
    'دفعة',
    'إيداع',
    'ايداع',
    'حسابك',
    'لحسابك',
    'بمبلغ',
    'مبلغ',
    'رصيد',
    'شيكل',
    'شيقل',
    'نيس',
    'payment',
    'transfer',
    'deposit',
    'wallet',
    'محفظة',
    'شحن',
    'شحن محفظة',
    'حساب جاري',
    'بقيمة',
    'من جوال',
    'jawwal pay',
    'جوال باي',
    'has been accepted',
    'has been credited',
    'transaction',
  ]);
}

function _hasBankOperationHints(fullTextLower: string): boolean {
  return _containsAny(fullTextLower, [
    'تحويل بنكي',
    'بنك فلسطين',
    'شيكل',
    'شيقل',
    'نيس',
    '₪',
    'ils',
    'nis',
    'jod',
    'usd',
  ]);
}

/** Digits + money/bank cue — aligns with Android [looksLikeMoneyFingerprintFromKnownBankApp]. */
function _looksLikeMoneyFingerprintFromKnownBankApp(fullTextLower: string): boolean {
  if (!/\d/.test(fullTextLower)) return false;
  return _containsAny(fullTextLower, [
    'مبلغ',
    'بمبلغ',
    'رصيد',
    'حساب',
    'حوالة',
    'عملية',
    'شيكل',
    'شيقل',
    'نيس',
    '₪',
    'ils',
    'nis',
    'jod',
    'usd',
    'eur',
    'gbp',
    'transfer',
    'payment',
    'deposit',
    'credit',
    'debit',
    'amount',
    'balance',
    'بنك',
    'bank',
    'bop',
    'palestine',
    'فلسطين',
    'تحويل بنكي',
    'إشعار',
    'اشعار',
    'إيداع',
    'ايداع',
    'استلام',
    'استقبال',
    'واردة',
    'وارد',
    'صادرة',
    'شحن',
    'بقيمة',
    'جاري',
    'transaction',
    'jawwal pay',
    'جوال باي',
    'iburaq',
    'البراق',
    'ايبرق',
  ]);
}

function _bankKeywordsMatch(fullTextLower: string): boolean {
  return (
    fullTextLower.includes('bank') ||
    fullTextLower.includes('بنك') ||
    fullTextLower.includes('bop') ||
    fullTextLower.includes('palestine') ||
    fullTextLower.includes('فلسطين') ||
    fullTextLower.includes('jawwal') ||
    fullTextLower.includes('palpay') ||
    fullTextLower.includes('جوال') ||
    fullTextLower.includes('بالباي') ||
    fullTextLower.includes('بال باي') ||
    fullTextLower.includes('ايبرق') ||
    fullTextLower.includes('البراق') ||
    fullTextLower.includes('iburaq') ||
    fullTextLower.includes('بنك فلسطين') ||
    fullTextLower.includes('pal pay') ||
    fullTextLower.includes('محفظة')
  );
}

/** Title + body must name a real bank/wallet (SMS-only gate; aligns with Android PaymentNotifyFilters). */
function _smsHasRecognizedPaymentBrand(fullTextLower: string): boolean {
  return _containsAny(fullTextLower, [
    'bop',
    'bank of palestine',
    'بنك فلسطين',
    'palestine bank',
    'bankofpalestine',
    'jawwal',
    'jawwal pay',
    'palpay',
    'pal pay',
    'بالباي',
    'بال باي',
    'جوال باي',
    'paypal',
    'pay pal',
    'iburaq',
    'البراق',
    'ايبرق',
    'stripe',
    'wise',
    'transferwise',
    'western union',
    'moneygram',
    'arab bank',
    'البنك العربي',
    'cairo amman',
    'القاهرة عمان',
    'qnb',
    'fab',
    'zain cash',
    'orange money',
    'cliq',
    'تحويل بنكي',
    'تحويل دفع',
    'الدفع لصديق',
    'دفع لصديق',
    'مصرف فلسطين',
    'efinance',
    'cash.pal',
    'wallet.ps',
  ]);
}

function _isExcludedPackage(packageNameLower: string): boolean {
  return _containsAny(packageNameLower, [
    'com.whatsapp',
    'org.telegram',
    'com.facebook.orca',
    'com.facebook.katana',
    'com.instagram.android',
    'com.snapchat.android',
    'com.google.android.gm',
    'com.linkedin.android',
  ]);
}

function _inferSourceFallback(packageNameLower: string, messageLower: string): string {
  if (_containsAny(packageNameLower, ['palpay'])) return 'PalPay';
  if (_containsAny(packageNameLower, ['jawwal', 'jawwalpay'])) return 'Jawwal Pay';
  if (_containsAny(packageNameLower, ['bank', 'bop', 'palestine', 'bankofpalestine', 'bop.mobile'])) {
    return 'Palestine Bank';
  }

  if (_isSmsAppPackage(packageNameLower) && _containsAny(messageLower, ['iburaq', 'ايبرق', 'البراق'])) {
    return 'Iburaq';
  }
  if (_isSmsAppPackage(packageNameLower)) return 'SMS Payment';
  return 'Other';
}

/** Known SMS gateway numbers or sender IDs for payment providers in Palestine/Middle East region. */
function _isRecognizedSmsSenderId(titleStr: string): boolean {
  const title = (titleStr || '').trim().toLowerCase();
  
  // Known payment provider SMS gateway sender IDs
  const recognizedSenders = [
    '1300',      // Palestine Telecom / Jawwal code
    '121',       // Jawwal short code
    '2222',      // Palestine Bank common gateway
    'bop',       // Palestine Bank direct
    'bank of palestine',
    'jawwal',
    'jawwal pay',
    'palpay',
    'iburaq',
    'البنك',
    'فلسطين',
    'جوال',
  ];
  
  // Do NOT accept random phone numbers (09x-xxx-xxxx pattern) as SMS senders
  // Payment providers use short codes or branded sender names, not personal numbers
  const looksLikePhoneNumber = /^0[0-9]{1,3}[-\s]?[0-9]{3}[-\s]?[0-9]{4}$/.test(title) ||
                               /^05[0-9][-\s]?[0-9]{3}[-\s]?[0-9]{4}$/.test(title);
  if (looksLikePhoneNumber) return false;
  
  // Check for recognized sender
  for (const sender of recognizedSenders) {
    if (title.includes(sender)) return true;
  }
  
  return false;
}

/**
 * Reject SMS from unknown/random senders (not recognized payment providers).
 * e.g. phone number in title = likely fake/forwarded message, not official SMS from bank/wallet.
 */
function _isUnrecognizedSmsSender(titleStr: string, messageLower: string): boolean {
  const title = (titleStr || '').trim().toLowerCase();
  
  // If title is a phone number, reject it unless message explicitly mentions recognition from known provider
  const looksLikePhoneNumber = /^0[0-9]{1,3}[-\s]?[0-9]{3}[-\s]?[0-9]{4}$/.test(title) ||
                               /^05[0-9][-\s]?[0-9]{3}[-\s]?[0-9]{4}$/.test(title);
  
  if (looksLikePhoneNumber) {
    // Allow only if message itself mentions recognized payment brand
    const hasBrandMention = _smsHasRecognizedPaymentBrand(`${title} ${messageLower}`);
    if (!hasBrandMention) return true; // Reject: phone number sender without payment brand
  }
  
  return false;
}

function _parseAndroidPaymentNotification(params: {
  packageName: string;
  title: string;
  message: string;
  receivedAt: Date;
}): {
  source: string;
  title: string;
  message: string;
  amount: number | null;
  currency?: string;
  transactionId?: string;
  direction: 'detected';
} | null {
  const packageLower = (params.packageName || '').toLowerCase();
  const messageNormalized = _stripTrailingAvailableBalanceLine(_normalizeDigits(params.message || ''));
  const titleLower = _normalizeDigits(params.title || '').toLowerCase();
  const messageLower = messageNormalized.toLowerCase();
  const haystack = `${packageLower} ${titleLower} ${messageLower}`;
  const combinedNormalized = _normalizeDigits(`${params.title || ''}\n${messageNormalized}`);

  if (_isExcludedPackage(packageLower)) return null;
  if (_isFalsePositive(haystack)) return null;
  if (_isLikelyNonPaymentJunk(haystack)) return null;

  const combinedLower = combinedNormalized.toLowerCase();
  if (_isInternalAccountTransferOnly(combinedLower)) return null;
  if (_isCardSpendExcluded(combinedLower)) return null;
  if (_isPromotionalMessageFromPaymentProvider(combinedLower)) return null;
  if (_isOutgoingOrServicePurchase(combinedLower)) return null;
  if (_isWhatsAppManualTransferInstruction(combinedLower)) return null;

  const fullText = `${titleLower} ${messageLower}`;
  const fullTextLower = fullText;

  const knownPayment = _isKnownPaymentAppPackage(packageLower);
  const smsPkg = _isSmsAppPackage(packageLower);
  if (smsPkg && !knownPayment && !_smsHasRecognizedPaymentBrand(fullTextLower)) {
    return null;
  }
  
  // For SMS: reject if sender is an unrecognized number (not a known payment provider SMS gateway).
  if (smsPkg && _isUnrecognizedSmsSender(params.title, messageLower)) {
    return null;
  }
  
  const strong = _hasStrongPaymentSignal(fullTextLower);
  const bankOpHints = _hasBankOperationHints(fullTextLower);
  const bankKw = _bankKeywordsMatch(fullTextLower);
  const iburaq = _containsAny(haystack, ['iburaq', 'ايبرق', 'البراق']);

  if (knownPayment) {
    if (!strong && !bankOpHints && !_looksLikeMoneyFingerprintFromKnownBankApp(fullTextLower)) return null;
  } else if (smsPkg && iburaq && strong) {
    // Iburaq SMS rail
  } else if (smsPkg && _isSmsIburaqIncomingWireLine(fullTextLower)) {
    // Iburaq SMS tray: حوالة واردة … بمبلغ … شيكل — often no "bank"/"jawwal" in body
  } else if (smsPkg && /\d/.test(fullTextLower) && strong) {
    // SMS: digits + strong payment phrase (sender may be only in title / OEM quirks)
  } else if (smsPkg && bankKw && (strong || _looksLikeMoneyFingerprintFromKnownBankApp(fullTextLower))) {
    // Generic bank SMS
  } else if (_isPalestineBankTransferLine(fullTextLower) && (strong || bankOpHints)) {
    // BOP mobile template; package name may not match known substrings on some devices
  } else if (
    _isPalestineBankFriendPaymentLine(fullTextLower) &&
    (strong || bankOpHints || _looksLikeMoneyFingerprintFromKnownBankApp(fullTextLower))
  ) {
    // BOP friend payment tray text (تحويل دفع لصديق) — not "تحويل بنكي"
  } else if (_isPalestineBankIncomingAccountLine(fullTextLower)) {
    // Incoming to account/wallet (often different from outgoing / تحويل بنكي)
  } else {
    return null;
  }

  const direction = 'detected' as const;

  let amountMatch =
    _amountAfterBimablagRegex.exec(combinedNormalized) ?? _amountAfterBimablagRegex.exec(messageNormalized);
  if (!amountMatch) {
    amountMatch = _amountAfterMablagRegex.exec(combinedNormalized) ?? _amountAfterMablagRegex.exec(messageNormalized);
  }
  if (!amountMatch) {
    amountMatch = _amountRegex.exec(combinedNormalized) ?? _amountRegex.exec(messageNormalized);
  }
  const parsedAmt = amountMatch ? _parseAmount(amountMatch[1]) : null;
  const resolvedAmount =
    parsedAmt != null && Number.isFinite(parsedAmt) && parsedAmt > 0 ? parsedAmt : null;

  const source =
    _detectSource(packageLower, titleLower, messageLower, haystack) ||
    _inferSourceFallback(packageLower, messageLower);

  let currency: string | undefined;
  if (resolvedAmount != null && amountMatch && amountMatch[2]) {
    const c = amountMatch[2].toUpperCase();
    if (c === '$' || c === 'US$') currency = 'USD';
    else if (c === 'JDS') currency = 'JOD';
    else currency = c;
  }

  const txMatch = _transactionIdRegex.exec(combinedNormalized) ?? _transactionIdRegex.exec(messageNormalized);
  const transactionId = txMatch?.[1];

  return {
    source,
    title: params.title,
    message: messageNormalized,
    amount: resolvedAmount,
    currency,
    transactionId: transactionId || undefined,
    direction,
  };
}

export const capturePaymentNotificationFromAndroid = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { packageName, title, message, receivedAt, notificationKey: notificationKeyRaw } = req.body ?? {};
    const pkg = String(packageName ?? '').trim();
    const titleStr = String(title ?? '').trim();
    const messageStr = String(message ?? '').trim();
    // Banks/wallets often put all text in title OR body only — require package + at least one non-empty line.
    if (!pkg || (!titleStr && !messageStr)) {
      res.status(200).json({ success: false, reason: 'Missing fields' });
      return;
    }

    const received = receivedAt ? new Date(receivedAt) : new Date();
    const notificationKey =
      typeof notificationKeyRaw === 'string' && notificationKeyRaw.trim().length > 0
        ? notificationKeyRaw.trim().slice(0, 512)
        : '';

    const parsed = _parseAndroidPaymentNotification({
      packageName: pkg,
      title: titleStr,
      message: messageStr,
      receivedAt: received,
    });

    if (!parsed) {
      res.status(200).json({ success: true, data: null, reason: 'Not a payment' });
      return;
    }

    const user = await User.findById(req.userId).select('_id').lean();
    if (!user) {
      res.status(201).json({ success: true, data: null });
      return;
    }

    // Do NOT dedupe by notificationKey alone: Samsung Messaging (and similar) reuse the same
    // StatusBarNotification key for the same thread when a new SMS updates the tray — returning
    // the first doc with that key would show the wrong payment (e.g. old wallet top-up vs new wire).

    const txId = parsed.transactionId ? String(parsed.transactionId).trim().toLowerCase() : '';

    if (txId) {
      const existing = await PaymentNotification.findOne({ userId: req.userId, transactionId: txId });
      if (existing) {
        res.status(201).json({ success: true, data: existing });
        return;
      }
    }

    const contentHash = _computePaymentContentHash({
      userId: String(req.userId),
      source: parsed.source,
      message: parsed.message,
      amount: parsed.amount,
      transactionId: txId || undefined,
      receivedAt: received,
    });
    const existingByContent = await PaymentNotification.findOne({
      userId: req.userId,
      contentHash,
    });
    if (existingByContent) {
      res.status(201).json({ success: true, data: existingByContent });
      return;
    }

    const created = await PaymentNotification.create({
      userId: req.userId,
      source: parsed.source,
      title: parsed.title,
      message: parsed.message,
      direction: parsed.direction,
      ...(parsed.amount != null ? { amount: parsed.amount } : {}),
      currency: parsed.currency,
      transactionId: txId || undefined,
      contentHash,
      ...(notificationKey ? { notificationKey } : {}),
      receivedAt: received,
    });

    res.status(201).json({ success: true, data: created });
    return;
  } catch (e) {
    next(e);
  }
};

export const getPaymentStats = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);
    const now = new Date();
    const thirtyDaysAgo = new Date(now);
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const [lastPayment, agg, daily] = await Promise.all([
      PaymentNotification.findOne({ userId: req.userId }).sort({ receivedAt: -1 }).lean(),
      PaymentNotification.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: null,
            totalAmount: { $sum: { $ifNull: ['$amount', 0] } },
            count: { $sum: 1 },
            incoming: { $sum: { $cond: [{ $eq: ['$direction', 'incoming'] }, 1, 0] } },
            outgoing: { $sum: { $cond: [{ $eq: ['$direction', 'outgoing'] }, 1, 0] } },
            unknown: { $sum: { $cond: [{ $eq: ['$direction', 'unknown'] }, 1, 0] } },
            detected: { $sum: { $cond: [{ $eq: ['$direction', 'detected'] }, 1, 0] } },
          },
        },
      ]),
      PaymentNotification.aggregate([
        {
          $match: {
            userId,
            receivedAt: { $gte: thirtyDaysAgo },
          },
        },
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m-%d', date: '$receivedAt' } },
            count: { $sum: 1 },
            sum: { $sum: { $ifNull: ['$amount', 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    ]);

    const g = agg[0] as
      | {
          totalAmount: number;
          count: number;
          incoming: number;
          outgoing: number;
          unknown: number;
          detected: number;
        }
      | undefined;

    res.json({
      success: true,
      data: {
        lastPayment,
        totalCount: g?.count ?? 0,
        totalAmount: g?.totalAmount ?? 0,
        incomingCount: g?.incoming ?? 0,
        outgoingCount: g?.outgoing ?? 0,
        unknownCount: g?.unknown ?? 0,
        detectedCount: g?.detected ?? 0,
        dailyLast30Days: daily.map((d) => ({
          date: d._id as string,
          count: d.count as number,
          sum: d.sum as number,
        })),
      },
    });
  } catch (e) {
    next(e);
  }
};

export const getPaymentNotifications = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit), 10) || 20));
    const skip = (page - 1) * limit;
    const filter: Record<string, unknown> = { userId: req.userId };

    const fromStr = String(req.query.from || '').trim();
    const toStr = String(req.query.to || '').trim();
    if (fromStr || toStr) {
      filter.receivedAt = {};
      if (fromStr) {
        const from = new Date(fromStr);
        if (!isNaN(from.getTime())) (filter.receivedAt as Record<string, Date>).$gte = from;
      }
      if (toStr) {
        const to = new Date(toStr);
        if (!isNaN(to.getTime())) (filter.receivedAt as Record<string, Date>).$lte = to;
      }
    }

    const exportAll = String(req.query.export ?? '').toLowerCase() === 'true';
    if (exportAll) {
      const data = await PaymentNotification.find(filter).sort({ receivedAt: -1 }).limit(5000).lean();
      const total = data.length;
      res.json({
        success: true,
        data: {
          data,
          total,
          page: 1,
          limit: total,
          totalPages: 1,
        },
      });
      return;
    }

    const [data, total] = await Promise.all([
      PaymentNotification.find(filter)
        .sort({ receivedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      PaymentNotification.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: {
        data,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (e) {
    next(e);
  }
};

export const deleteAllPaymentNotifications = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const result = await PaymentNotification.deleteMany({ userId: req.userId });
    res.json({
      success: true,
      data: {
        deletedCount: result.deletedCount ?? 0,
      },
    });
  } catch (e) {
    next(e);
  }
};

export const deletePaymentNotification = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { id } = req.params;
    const deleted = await PaymentNotification.findOneAndDelete({
      _id: id,
      userId: req.userId,
    });
    if (!deleted) {
      next(new BadRequestError('Payment notification not found'));
      return;
    }
    res.json({ success: true, data: { deleted: true } });
  } catch (e) {
    next(e);
  }
};

export const updatePaymentNotificationDirection = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { id } = req.params;
    const { direction } = req.body ?? {};
    if (
      direction !== 'incoming' &&
      direction !== 'outgoing' &&
      direction !== 'unknown' &&
      direction !== 'detected'
    ) {
      next(new BadRequestError('direction must be incoming, outgoing, unknown, or detected'));
      return;
    }
    const updated = await PaymentNotification.findOneAndUpdate(
      { _id: id, userId: req.userId },
      { $set: { direction } },
      { new: true }
    ).lean();
    if (!updated) {
      next(new BadRequestError('Payment notification not found'));
      return;
    }
    res.json({ success: true, data: updated });
  } catch (e) {
    next(e);
  }
};

export const getNotifications = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit), 10) || 20));
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      Notification.find({ userId: req.userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Notification.countDocuments({ userId: req.userId }),
    ]);

    res.json({
      success: true,
      data: {
        data,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (e) {
    next(e);
  }
};

export const markAsRead = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { id } = req.params;
    const updated = await Notification.findOneAndUpdate(
      { _id: id, userId: req.userId },
      { isRead: true },
      { new: true }
    );
    if (!updated) {
      next(new BadRequestError('Notification not found'));
      return;
    }
    res.json({ success: true, data: updated });
  } catch (e) {
    next(e);
  }
};
