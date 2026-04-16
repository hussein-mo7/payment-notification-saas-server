import '../loadEnv';

const required = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
};

const optional = (key: string, defaultValue: string): string => {
  return process.env[key] ?? defaultValue;
};

export const config = {
  env: optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '5000'), 10),

  mongodb: {
    uri: required('MONGODB_URI'),
  },

  jwt: {
    accessSecret: required('JWT_ACCESS_SECRET'),
    refreshSecret: required('JWT_REFRESH_SECRET'),
    /** Web sessions default to 30d; mobile sessions can be kept long-lived. */
    accessExpiresIn: optional('JWT_ACCESS_EXPIRES_IN', '30d'),
    refreshExpiresIn: optional('JWT_REFRESH_EXPIRES_IN', '30d'),
    mobileRefreshExpiresIn: optional('JWT_MOBILE_REFRESH_EXPIRES_IN', '3650d'),
  },

  urls: {
    frontend: optional('FRONTEND_URL', 'http://localhost:3000'),
    admin: optional('ADMIN_URL', 'http://localhost:5173'),
  },

  keepAlive: {
    url: optional('KEEP_ALIVE_URL', ''),
  },
} as const;
