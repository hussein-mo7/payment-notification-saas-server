import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  fullName: string;
  email: string;
  phoneNumber: string;
  passwordHash: string;
  /** Separate bcrypt hash for read-only app login (same email). Not the main password. */
  viewerPasswordHash?: string;
  emailVerified: boolean;
  verificationToken?: string;
  verificationTokenExpires?: Date;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  subscriptionStart?: Date;
  subscriptionEnd?: Date;
  currentSubscriptionPrice?: number;
  currentSubscriptionCurrency?: string;
  /**
   * Current subscription monthly price (for quick display in lists).
   * Detailed history is stored in SubscriptionPayment documents.
   */
  targetEmail: string; // where to forward notifications; defaults to email
  /** Set when we sent the \"2 days before expiry\" in-app reminder for this subscriptionEnd. */
  subscriptionExpiryReminderSentFor?: Date;
  lastSubscriptionWarningSentAt?: Date;
  /** Screenshot / proof of subscription payment (Cloudinary URL) — latest upload. */
  subscriptionPaymentProofUrl?: string;
  /** Cloudinary public_id for the latest proof image. */
  subscriptionPaymentProofPublicId?: string;
  subscriptionPaymentProofUploadedAt?: Date;
  /** Set when an admin marks the current proof as reviewed (cleared on new upload). */
  subscriptionPaymentProofReviewedAt?: Date;
  /** All uploaded proofs (newest appends); older images are kept for admin review. */
  subscriptionPaymentProofHistory?: Array<{
    _id?: mongoose.Types.ObjectId;
    url: string;
    publicId: string;
    uploadedAt: Date;
    reviewedAt?: Date;
  }>;
  /** User-selected renewal period (shown to admin with payment proof). */
  subscriptionPlanPreference?: 'week' | 'month' | 'year';
  refreshTokens?: string[];
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phoneNumber: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true, select: false },
    viewerPasswordHash: { type: String, select: false },
    emailVerified: { type: Boolean, default: false },
    verificationToken: { type: String, select: false },
    verificationTokenExpires: { type: Date, select: false },
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpires: { type: Date, select: false },
    subscriptionStart: { type: Date },
    subscriptionEnd: { type: Date },
    currentSubscriptionPrice: { type: Number },
    currentSubscriptionCurrency: { type: String },
    targetEmail: { type: String, trim: true }, // defaults to email in pre-save
    subscriptionExpiryReminderSentFor: { type: Date },
    lastSubscriptionWarningSentAt: { type: Date },
    subscriptionPaymentProofUrl: { type: String, trim: true },
    subscriptionPaymentProofPublicId: { type: String, trim: true, select: false },
    subscriptionPaymentProofUploadedAt: { type: Date },
    subscriptionPaymentProofReviewedAt: { type: Date },
    subscriptionPlanPreference: {
      type: String,
      enum: ['week', 'month', 'year'],
      trim: true,
    },
    // Allow multiple concurrent refresh tokens (one per device/session)
    refreshTokens: { type: [String], select: false },
  },
  { timestamps: true }
);

userSchema.index({ subscriptionEnd: 1 });

const subscriptionProofItemSchema = new Schema(
  {
    url: { type: String, required: true, trim: true },
    publicId: { type: String, required: true, trim: true },
    uploadedAt: { type: Date, required: true },
    reviewedAt: { type: Date },
  },
  { _id: true }
);

userSchema.add({
  subscriptionPaymentProofHistory: { type: [subscriptionProofItemSchema], default: undefined },
});

userSchema.pre('save', function (next) {
  if (this.isNew && !this.targetEmail) {
    this.targetEmail = this.email;
  }
  next();
});

export const User = mongoose.model<IUser>('User', userSchema);
