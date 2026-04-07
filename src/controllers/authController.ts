import { randomBytes } from 'crypto';
import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { User } from '../models';
import { BadRequestError, UnauthorizedError, NotFoundError } from '../utils/errors';
import { AccessMode } from '../types';
import { generateAccessToken, generateRefreshToken, verifyRefreshToken, randomVerificationCode } from '../utils/tokens';
import { normalizeVerificationInput } from '../utils/verificationInput';
import { config } from '../config';
import { sendPasswordResetEmail, sendVerificationEmail } from '../services/verificationEmail';
import { getPasswordPolicyMessage } from '../utils/passwordPolicy';
import { VERIFICATION_TTL_MS } from '../constants/verification';

/** Password reset token lifetime (email link). */
const PASSWORD_RESET_TTL_MS = 24 * 60 * 60 * 1000;

const SALT_ROUNDS = 12;

async function completeEmailVerification(
  rawInput: string
): Promise<{ ok: true } | { ok: false; message: string }> {
  const t = normalizeVerificationInput(rawInput);
  if (!t) {
    return { ok: false, message: 'Verification code required' };
  }

  const user = await User.findOne({
    verificationToken: t,
    verificationTokenExpires: { $gt: new Date() },
  }).select('+verificationToken +verificationTokenExpires');

  if (!user) {
    return { ok: false, message: 'Invalid or expired verification code' };
  }

  user.emailVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpires = undefined;
  await user.save({ validateBeforeSave: false });
  return { ok: true };
}

export const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { fullName, email, phoneNumber, password } = req.body;

    if (!fullName || !email || !phoneNumber || !password) {
      next(new BadRequestError('fullName, email, phoneNumber and password are required'));
      return;
    }

    const passwordPolicy = getPasswordPolicyMessage(password);
    if (passwordPolicy) {
      next(new BadRequestError(passwordPolicy));
      return;
    }

    const existing = await User.findOne({ $or: [{ email }, { phoneNumber }] });
    if (existing) {
      next(new BadRequestError(existing.email === email ? 'Email already registered' : 'Phone number already registered'));
      return;
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const emailLower = email.toLowerCase().trim();
    const locale: 'en' | 'ar' = req.body?.locale === 'ar' || req.body?.language === 'ar' ? 'ar' : 'en';
    const verificationToken = randomVerificationCode();
    const verificationTokenExpires = new Date(Date.now() + VERIFICATION_TTL_MS);

    await User.create({
      fullName: fullName.trim(),
      email: emailLower,
      phoneNumber: phoneNumber.trim(),
      passwordHash,
      targetEmail: emailLower,
      emailVerified: false,
      verificationToken,
      verificationTokenExpires,
    });

    // Defer to next event loop so the HTTP response is fully flushed first (Render / proxies).
    setImmediate(() => {
      void sendVerificationEmail(emailLower, verificationToken, locale)
        .then((emailResult) => {
          if (!emailResult.sent) {
            console.error('[register] Verification email not sent:', emailResult.detail ?? 'unknown');
          }
        })
        .catch((err) => {
          console.error('[register] Verification email threw:', err);
        });
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please verify your email.',
      requiresEmailVerification: true,
      verificationEmailPending: true,
    });
  } catch (e) {
    next(e);
    return;
  }
};

export const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const identifier = String(req.body.email ?? req.body.emailOrPhone ?? '').trim();
    const { password } = req.body;

    if (!identifier || !password) {
      next(new BadRequestError('Email or phone and password are required'));
      return;
    }

    const query: Record<string, unknown> = identifier.includes('@')
      ? { email: identifier.toLowerCase() }
      : {
          $or: [
            { phoneNumber: identifier },
            ...((): Array<{ phoneNumber: string }> => {
              const digits = identifier.replace(/\D/g, '');
              if (digits.length >= 6 && digits !== identifier) {
                return [{ phoneNumber: digits }];
              }
              return [];
            })(),
          ],
        };

    const user = await User.findOne(query).select('+passwordHash +emailVerified +refreshTokens');

    if (!user) {
      next(new UnauthorizedError('Invalid credentials'));
      return;
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      next(new UnauthorizedError('Invalid credentials'));
      return;
    }

    if (!user.emailVerified) {
      next(
        new UnauthorizedError(
          'Please verify your email before signing in. Check your inbox or request a new verification email in the app.'
        )
      );
      return;
    }

    const accessToken = generateAccessToken(user._id.toString(), 'full');
    const refreshToken = generateRefreshToken(user._id.toString(), 'full');
    // Append new refresh token to the user's token list (keep other sessions alive)
    user.refreshTokens = Array.isArray(user.refreshTokens) ? user.refreshTokens.concat(refreshToken) : [refreshToken];
    await user.save({ validateBeforeSave: false });

    res.json({
      success: true,
      accessToken,
      refreshToken,
      accessMode: 'full' as const,
      expiresIn: config.jwt.accessExpiresIn,
    });
  } catch (e) {
    next(e);
  }
};

/** Read-only session: same account as main (email or phone), viewer password from Settings. */
export const loginViewer = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const identifier = String(req.body.emailOrPhone ?? req.body.email ?? '').trim();
    const { password } = req.body;

    if (!identifier || !password) {
      next(new BadRequestError('Email or phone and viewer password are required'));
      return;
    }

    const query: Record<string, unknown> = identifier.includes('@')
      ? { email: identifier.toLowerCase() }
      : {
          $or: [
            { phoneNumber: identifier },
            ...((): Array<{ phoneNumber: string }> => {
              const digits = identifier.replace(/\D/g, '');
              if (digits.length >= 6 && digits !== identifier) {
                return [{ phoneNumber: digits }];
              }
              return [];
            })(),
          ],
        };

    const user = await User.findOne(query).select('+viewerPasswordHash +emailVerified +refreshTokens');

    if (!user) {
      next(new UnauthorizedError('Invalid credentials'));
      return;
    }

    if (!user.emailVerified) {
      next(
        new UnauthorizedError(
          'Please verify the main account email before using viewer login.'
        )
      );
      return;
    }

    if (!user.viewerPasswordHash) {
      next(
        new UnauthorizedError(
          'Viewer access is not set up yet. Sign in with the main account and set a viewer password in Settings.'
        )
      );
      return;
    }

    const valid = await bcrypt.compare(password, user.viewerPasswordHash);
    if (!valid) {
      next(new UnauthorizedError('Invalid credentials'));
      return;
    }

    const mode: AccessMode = 'viewer';
    const accessToken = generateAccessToken(user._id.toString(), mode);
    const refreshToken = generateRefreshToken(user._id.toString(), mode);
    user.refreshTokens = Array.isArray(user.refreshTokens) ? user.refreshTokens.concat(refreshToken) : [refreshToken];
    await user.save({ validateBeforeSave: false });

    res.json({
      success: true,
      accessToken,
      refreshToken,
      accessMode: 'viewer' as const,
      expiresIn: config.jwt.accessExpiresIn,
    });
  } catch (e) {
    next(e);
  }
};

export const refresh = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      next(new BadRequestError('Refresh token required'));
      return;
    }

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.userId).select('+refreshTokens');
    if (!user || !Array.isArray(user.refreshTokens) || !user.refreshTokens.includes(refreshToken)) {
      next(new UnauthorizedError('Invalid refresh token'));
      return;
    }

    const mode: AccessMode = decoded.accessMode === 'viewer' ? 'viewer' : 'full';
    const accessToken = generateAccessToken(user._id.toString(), mode);
    const newRefreshToken = generateRefreshToken(user._id.toString(), mode);
    // Rotate: replace the used token with the new one, keep others
    user.refreshTokens = (user.refreshTokens || []).map((t) => (t === refreshToken ? newRefreshToken : t));
    await user.save({ validateBeforeSave: false });

    res.json({
      success: true,
      accessToken,
      refreshToken: newRefreshToken,
      accessMode: mode,
      expiresIn: config.jwt.accessExpiresIn,
    });
  } catch (e) {
    next(e);
  }
};

export const forgotPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const emailRaw = req.body?.email;
    const email = String(emailRaw ?? '')
      .trim()
      .toLowerCase();
    if (!email) {
      next(new BadRequestError('Email is required'));
      return;
    }

    const genericResponse = {
      success: true,
      message:
        'If an account exists for this email, you will receive a password reset link. It expires in 24 hours.',
    };

    const user = await User.findOne({ email }).select('+resetPasswordToken +resetPasswordExpires');
    if (!user) {
      res.json(genericResponse);
      return;
    }

    const token = randomBytes(32).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = new Date(Date.now() + PASSWORD_RESET_TTL_MS);
    await user.save({ validateBeforeSave: false });

    const locale: 'en' | 'ar' = req.body?.locale === 'ar' || req.body?.language === 'ar' ? 'ar' : 'en';

    setImmediate(() => {
      void sendPasswordResetEmail(email, token, locale)
        .then((emailResult) => {
          if (!emailResult.sent) {
            console.error('[forgotPassword] Reset email not sent:', emailResult.detail ?? 'unknown');
          }
        })
        .catch((err) => {
          console.error('[forgotPassword] Reset email threw:', err);
        });
    });

    res.json(genericResponse);
  } catch (e) {
    next(e);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      next(new BadRequestError('Token and new password are required'));
      return;
    }

    const passwordPolicy = getPasswordPolicyMessage(password);
    if (passwordPolicy) {
      next(new BadRequestError(passwordPolicy));
      return;
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    }).select('+resetPasswordToken +resetPasswordExpires');

    if (!user) {
      next(new BadRequestError('Invalid or expired reset token'));
      return;
    }

    user.passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (e) {
    next(e);
  }
};

export const verifyEmail = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const q = req.query;
    const raw =
      (typeof q.code === 'string' && q.code) ||
      (typeof q.token === 'string' && q.token) ||
      '';
    const result = await completeEmailVerification(raw);
    if (!result.ok) {
      next(new BadRequestError(result.message));
      return;
    }
    res.json({ success: true, message: 'Email verified successfully' });
  } catch (e) {
    next(e);
  }
};

/** JSON `{ "code": "123456" }` or `{ "token": "..." }` (legacy). */
export const verifyEmailPost = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const raw = String(req.body?.code ?? req.body?.token ?? '').trim();
    const result = await completeEmailVerification(raw);
    if (!result.ok) {
      next(new BadRequestError(result.message));
      return;
    }
    res.json({ success: true, message: 'Email verified successfully' });
  } catch (e) {
    next(e);
  }
};

export const resendVerification = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { email } = req.body ?? {};
    const emailLower = String(email ?? '')
      .trim()
      .toLowerCase();
    if (!emailLower) {
      next(new BadRequestError('Email is required'));
      return;
    }

    const user = await User.findOne({ email: emailLower }).select(
      '+verificationToken +verificationTokenExpires'
    );

    if (!user || user.emailVerified) {
      // Do not set verificationEmailSent — client must not treat this as "email delivered"
      // (same response whether unknown email or already verified; avoids account enumeration).
      res.json({
        success: true,
        message:
          'If this address is registered and still needs verification, use Resend again after checking the email is correct.',
      });
      return;
    }

    const locale: 'en' | 'ar' = req.body?.locale === 'ar' || req.body?.language === 'ar' ? 'ar' : 'en';
    const verificationToken = randomVerificationCode();
    const verificationTokenExpires = new Date(Date.now() + VERIFICATION_TTL_MS);
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = verificationTokenExpires;
    await user.save({ validateBeforeSave: false });
    const emailResult = await sendVerificationEmail(user.email, verificationToken, locale);
    if (!emailResult.sent) {
      console.error('[resend-verification] Email not sent:', emailResult.detail ?? 'unknown');
    } else {
      console.log('[resend-verification] Brevo accepted for', user.email);
    }

    res.json({
      success: true,
      message: 'Verification email sent. Check your inbox and spam folder.',
      verificationEmailSent: emailResult.sent,
    });
  } catch (e) {
    next(e);
  }
};
