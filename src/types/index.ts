import { Request } from 'express';
import { Types } from 'mongoose';

export type NotificationType = 'system' | 'admin';

export type AccessMode = 'full' | 'viewer';

export type SessionType = 'web' | 'mobile';

export interface JwtPayload {
  userId: string;
  type: 'access' | 'refresh' | 'admin';
  /** Present on user access/refresh tokens; omitted on legacy tokens (treated as full). */
  accessMode?: AccessMode;
  /** Session flavor used to control token lifetime. */
  sessionType?: SessionType;
}

export interface AuthRequest extends Request {
  userId?: string;
  /** Set by [authenticate] for user access tokens. */
  accessMode?: AccessMode;
}

export interface PaginationQuery {
  page?: string;
  limit?: string;
}

export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

// Re-export for models
export type ObjectId = Types.ObjectId;
