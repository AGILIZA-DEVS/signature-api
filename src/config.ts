/**
 * Configuration management with environment variables
 */

export interface SignatureConfig {
  debug: boolean;
  logLevel: string;
  defaultHashAlgorithm: string;
  certificateValidationTimeout: number;
  strictICPValidation: boolean;
  enableCRLCheck: boolean;
  crlCacheTimeout: number;
  customCRLUrls: string[];
  maxDocumentSize: number;
  maxSignaturesPerDocument: number;
  networkTimeout: number;
  httpProxy?: string;
  httpsProxy?: string;
  enableExtendedValidation: boolean;
  minRSAKeySize: number;
  skipCertValidation: boolean;
  testMode: boolean;
}

/**
 * Get configuration from environment variables with defaults
 */
export function getConfig(): SignatureConfig {
  return {
    debug: process.env.DEBUG_SIGNATURE === 'true',
    logLevel: process.env.LOG_LEVEL || 'info',
    defaultHashAlgorithm: process.env.DEFAULT_HASH_ALGORITHM || 'SHA-256',
    certificateValidationTimeout: parseInt(process.env.CERTIFICATE_VALIDATION_TIMEOUT || '30000'),
    strictICPValidation: process.env.STRICT_ICP_VALIDATION !== 'false',
    enableCRLCheck: process.env.ENABLE_CRL_CHECK === 'true',
    crlCacheTimeout: parseInt(process.env.CRL_CACHE_TIMEOUT || '3600'),
    customCRLUrls: process.env.CUSTOM_CRL_URLS ? process.env.CUSTOM_CRL_URLS.split(',') : [],
    maxDocumentSize: parseInt(process.env.MAX_DOCUMENT_SIZE || '52428800'), // 50MB
    maxSignaturesPerDocument: parseInt(process.env.MAX_SIGNATURES_PER_DOCUMENT || '100'),
    networkTimeout: parseInt(process.env.NETWORK_TIMEOUT || '10000'),
    httpProxy: process.env.HTTP_PROXY,
    httpsProxy: process.env.HTTPS_PROXY,
    enableExtendedValidation: process.env.ENABLE_EXTENDED_VALIDATION !== 'false',
    minRSAKeySize: parseInt(process.env.MIN_RSA_KEY_SIZE || '2048'),
    skipCertValidation: process.env.SKIP_CERT_VALIDATION === 'true',
    testMode: process.env.TEST_MODE === 'true'
  };
}

/**
 * Validate configuration values
 */
export function validateConfig(config: SignatureConfig): string[] {
  const errors: string[] = [];

  if (config.certificateValidationTimeout < 1000) {
    errors.push('CERTIFICATE_VALIDATION_TIMEOUT must be at least 1000ms');
  }

  if (config.maxDocumentSize < 1024) {
    errors.push('MAX_DOCUMENT_SIZE must be at least 1KB');
  }

  if (config.minRSAKeySize < 1024) {
    errors.push('MIN_RSA_KEY_SIZE must be at least 1024 bits');
  }

  if (!['SHA-256', 'SHA-384', 'SHA-512'].includes(config.defaultHashAlgorithm)) {
    errors.push('DEFAULT_HASH_ALGORITHM must be SHA-256, SHA-384, or SHA-512');
  }

  return errors;
}

// Export singleton config
export const config = getConfig();