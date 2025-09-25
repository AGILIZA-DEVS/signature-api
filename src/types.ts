export interface SignatureOptions {
  /** Certificate PKCS#12 buffer (.p12/.pfx) */
  certificate: Buffer;
  /** Password for certificate */
  password: string;
  /** Hash algorithm (default: 'SHA-256') */
  hashAlgorithm?: string;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

export interface SignedDocument {
  /** Original document buffer */
  document: Buffer;
  /** Document format (pdf, docx, etc.) */
  format: string;
  /** Document name/identifier */
  name: string;
}

export interface SignatureResult {
  /** PKCS#7 signature data in base64 */
  signatureData: string;
  /** Signer certificate */
  signerCertificate: Buffer;
  /** Signature algorithm used */
  signatureAlgorithm: string;
  /** Hash algorithm used */
  hashAlgorithm: string;
  /** Signature timestamp */
  timestamp: Date;
  /** Certificate information */
  certificateInfo: ICertificateInfo;
  /** Validation result */
  isValid: boolean;
}

export interface ICertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validity: {
    notBefore: Date;
    notAfter: Date;
  };
  cpfCnpj?: string;
  keyUsage: string[];
  extendedKeyUsage: string[];
  policies: string[];
  publicKey: {
    algorithm: string;
    size: number;
  };
}

export interface IValidationResult {
  cryptographicIntegrity: boolean;
  certificateChain: boolean;
  revocationStatus: boolean;
  timeValidation: boolean;
  policyCompliance: boolean;
  errors: string[];
  warnings: string[];
  validatedAt: Date;
}

export interface IPKCS7SignatureData {
  signatureData: string;
  signerCertificate: Buffer;
  timestampData?: string;
  signatureAlgorithm: string;
  hashAlgorithm: string;
  signedAttributes: any;
  unsignedAttributes?: any;
}