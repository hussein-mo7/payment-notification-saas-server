import { Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { User } from '../models';
import { AuthRequest } from '../types';
import { BadRequestError, NotFoundError } from '../utils/errors';
import { getPasswordPolicyMessage } from '../utils/passwordPolicy';
import {
  destroySubscriptionProofImage,
  isCloudinaryConfigured,
  uploadSubscriptionProofImage,
} from '../services/cloudinarySubscriptionProof';
import { optimizePaymentProofImage } from '../services/optimizePaymentProofImage';
import {
  normalizeClientProofHistory,
  SUBSCRIPTION_PROOF_HISTORY_MAX,
} from '../utils/subscriptionProofHistory';

const SALT_ROUNDS = 12;

const toProfileResponse = (user: Record<string, unknown>) => {
  const subscriptionEndRaw = user.subscriptionEnd;
  const endDate =
    typeof subscriptionEndRaw === 'string' || subscriptionEndRaw instanceof Date
      ? new Date(subscriptionEndRaw)
      : null;
  const now = new Date();
  const hasValidEnd = !!endDate && !Number.isNaN(endDate.getTime());
  const isActive = hasValidEnd && endDate > now;

  return {
    ...user,
    subscriptionStatus: isActive ? 'active' : 'inactive',
    isSubscriptionActive: isActive,
  };
};

export const getProfile = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const baseSelect =
      '-passwordHash -refreshTokens -verificationToken -verificationTokenExpires -resetPasswordToken -resetPasswordExpires';
    const user = await User.findById(req.userId)
      .select(req.accessMode === 'viewer' ? baseSelect : `${baseSelect} +viewerPasswordHash`)
      .lean();
    if (!user) {
      next(new NotFoundError('User not found'));
      return;
    }
    const u = user as Record<string, unknown>;
    const viewerPasswordConfigured =
      req.accessMode === 'viewer' ? undefined : !!(u.viewerPasswordHash as string | undefined);
    delete u.viewerPasswordHash;
    const { subscriptionPaymentProofHistory: _hist, ...rest } = u;
    const data: Record<string, unknown> = {
      ...toProfileResponse(rest),
      subscriptionPaymentProofHistory: normalizeClientProofHistory(
        user as Parameters<typeof normalizeClientProofHistory>[0]
      ),
    };
    if (viewerPasswordConfigured !== undefined) {
      data.viewerPasswordConfigured = viewerPasswordConfigured;
    }
    res.json({ success: true, data });
  } catch (e) {
    next(e);
  }
};

const SUBSCRIPTION_PLAN_VALUES = new Set(['week', 'month']);

export const updateProfile = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { fullName, targetEmail, phoneNumber, subscriptionPlanPreference } = req.body;
    const allowed: Record<string, string> = {};
    if (fullName !== undefined) allowed.fullName = String(fullName).trim();
    if (targetEmail !== undefined) allowed.targetEmail = String(targetEmail).trim();
    if (subscriptionPlanPreference !== undefined) {
      const p = String(subscriptionPlanPreference).trim().toLowerCase();
      if (!SUBSCRIPTION_PLAN_VALUES.has(p)) {
        next(new BadRequestError('subscriptionPlanPreference must be week or month'));
        return;
      }
      allowed.subscriptionPlanPreference = p;
    }
    if (phoneNumber !== undefined) {
      const p = String(phoneNumber).trim();
      if (!p) {
        next(new BadRequestError('phoneNumber cannot be empty'));
        return;
      }
      const taken = await User.findOne({ phoneNumber: p, _id: { $ne: req.userId } }).select('_id').lean();
      if (taken) {
        next(new BadRequestError('Phone number already in use'));
        return;
      }
      allowed.phoneNumber = p;
    }

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: allowed },
      { new: true, runValidators: true }
    ).select('-passwordHash -refreshTokens -verificationToken -verificationTokenExpires -resetPasswordToken -resetPasswordExpires');

    if (!user) {
      next(new NotFoundError('User not found'));
      return;
    }
    const obj = user.toObject() as unknown as Record<string, unknown>;
    const { subscriptionPaymentProofHistory: _ph, ...rest } = obj;
    res.json({
      success: true,
      data: {
        ...toProfileResponse(rest),
        subscriptionPaymentProofHistory: normalizeClientProofHistory(
          user.toObject() as Parameters<typeof normalizeClientProofHistory>[0]
        ),
      },
    });
  } catch (e) {
    next(e);
  }
};

export const uploadSubscriptionPaymentProof = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!isCloudinaryConfigured()) {
      next(new BadRequestError('Payment proof upload is not configured on the server (Cloudinary)'));
      return;
    }
    const file = (req as AuthRequest & { file?: Express.Multer.File }).file;
    if (!file?.buffer) {
      next(new BadRequestError('Image file is required (use field name: image)'));
      return;
    }

    const existing = await User.findById(req.userId).select('+subscriptionPaymentProofPublicId').lean();
    if (!existing) {
      next(new NotFoundError('User not found'));
      return;
    }

    const planPref = String(
      (existing as { subscriptionPlanPreference?: string }).subscriptionPlanPreference || ''
    )
      .trim()
      .toLowerCase();
    if (planPref !== 'week' && planPref !== 'month') {
      next(
        new BadRequestError(
          'Select your subscription plan (week or month) in the app before uploading payment proof.'
        )
      );
      return;
    }

    const optimized = await optimizePaymentProofImage(file.buffer);
    const { url, publicId } = await uploadSubscriptionProofImage(optimized);

    type HistEntry = { url: string; publicId: string; uploadedAt: Date; reviewedAt?: Date };
    let history: HistEntry[] = Array.isArray(existing.subscriptionPaymentProofHistory)
      ? (existing.subscriptionPaymentProofHistory as HistEntry[]).map((h) => ({
          url: h.url,
          publicId: h.publicId,
          uploadedAt: new Date(h.uploadedAt),
          ...(h.reviewedAt ? { reviewedAt: new Date(h.reviewedAt) } : {}),
        }))
      : [];

    if (
      history.length === 0 &&
      existing.subscriptionPaymentProofUrl &&
      existing.subscriptionPaymentProofPublicId
    ) {
      history.push({
        url: existing.subscriptionPaymentProofUrl,
        publicId: existing.subscriptionPaymentProofPublicId,
        uploadedAt: existing.subscriptionPaymentProofUploadedAt
          ? new Date(existing.subscriptionPaymentProofUploadedAt)
          : new Date(0),
        ...(existing.subscriptionPaymentProofReviewedAt
          ? { reviewedAt: new Date(existing.subscriptionPaymentProofReviewedAt) }
          : {}),
      });
    }

    history.push({
      url,
      publicId,
      uploadedAt: new Date(),
    });

    while (history.length > SUBSCRIPTION_PROOF_HISTORY_MAX) {
      const removed = history.shift();
      if (removed?.publicId) {
        await destroySubscriptionProofImage(removed.publicId);
      }
    }

    const updated = await User.findByIdAndUpdate(
      req.userId,
      {
        $set: {
          subscriptionPaymentProofHistory: history,
          subscriptionPaymentProofUrl: url,
          subscriptionPaymentProofPublicId: publicId,
          subscriptionPaymentProofUploadedAt: new Date(),
        },
        $unset: { subscriptionPaymentProofReviewedAt: '' },
      },
      { new: true, runValidators: true }
    ).select(
      '-passwordHash -refreshTokens -verificationToken -verificationTokenExpires -resetPasswordToken -resetPasswordExpires -subscriptionPaymentProofPublicId'
    );

    if (!updated) {
      next(new NotFoundError('User not found'));
      return;
    }

    const plain = updated.toObject() as unknown as Record<string, unknown>;
    delete plain.subscriptionPaymentProofPublicId;
    delete plain.subscriptionPaymentProofHistory;

    res.json({
      success: true,
      data: {
        ...toProfileResponse(plain),
        subscriptionPaymentProofHistory: normalizeClientProofHistory(
          updated.toObject() as Parameters<typeof normalizeClientProofHistory>[0]
        ),
      },
    });
  } catch (e) {
    next(e);
  }
};

export const changePassword = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      next(new BadRequestError('currentPassword and newPassword are required'));
      return;
    }

    const passwordPolicy = getPasswordPolicyMessage(newPassword);
    if (passwordPolicy) {
      next(new BadRequestError(passwordPolicy));
      return;
    }

    const user = await User.findById(req.userId).select('+passwordHash');
    if (!user) {
      next(new NotFoundError('User not found'));
      return;
    }

    const valid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!valid) {
      next(new BadRequestError('Current password is incorrect'));
      return;
    }

    user.passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await user.save();
    res.json({ success: true, message: 'Password updated' });
  } catch (e) {
    next(e);
  }
};

export const setViewerPassword = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { password } = req.body ?? {};
    if (!password || typeof password !== 'string') {
      next(new BadRequestError('password is required'));
      return;
    }

    const passwordPolicy = getPasswordPolicyMessage(password);
    if (passwordPolicy) {
      next(new BadRequestError(passwordPolicy));
      return;
    }

    const user = await User.findById(req.userId);
    if (!user) {
      next(new NotFoundError('User not found'));
      return;
    }

    user.viewerPasswordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await user.save({ validateBeforeSave: false });

    res.json({ success: true, message: 'Viewer password updated' });
  } catch (e) {
    next(e);
  }
};
