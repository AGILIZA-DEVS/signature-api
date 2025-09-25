export const ICP_BRASIL_OIDS = {
  CPF: '2.16.76.1.3.1',
  CNPJ: '2.16.76.1.3.2',
  POLICY_A1: '2.16.76.1.2.1.1',
  POLICY_A3: '2.16.76.1.2.1.3',
  POLICY_A4: '2.16.76.1.2.1.4',
  POLICY_SYNGULAR: '2.16.76.1.2.1.133',
  KEY_USAGE: '2.5.29.15',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  CERTIFICATE_POLICIES: '2.5.29.32',
  PESSOA_FISICA: '2.16.76.1.3.1',
  PESSOA_JURIDICA: '2.16.76.1.3.2',
  EQUIPAMENTO: '2.16.76.1.3.3',
  APLICACAO: '2.16.76.1.3.4',
} as const;

export const CRL_URLS = {
  AC_RAIZ: 'http://acraiz.icpbrasil.gov.br/LCRacraiz.crl',
  SERPRO: 'http://repositorio.serpro.gov.br/lcr/acserpro/acserpro.crl',
  CERTISIGN: 'http://crl.certisign.com.br/certisignac.crl',
  SERASA: 'http://crl.serasa.com.br/serasacd.crl',
  VALID: 'http://ccd.valid.com.br/lcr/ac-valid-brasil-v5.crl',
  SAFENET: 'http://crl.safenet-inc.com/brazilian-ac-safenet.crl',
} as const;

export const ICP_ERROR_CODES = {
  INVALID_CERTIFICATE: 'CERT_001',
  CERTIFICATE_EXPIRED: 'CERT_002',
  CERTIFICATE_REVOKED: 'CERT_003',
  INVALID_CHAIN: 'CERT_004',
  INVALID_POLICY: 'CERT_005',
  CRL_UNAVAILABLE: 'CERT_006',
  CERTIFICATE_NOT_ICP_BRASIL: 'CERT_007',
  INVALID_CPF_CNPJ: 'CERT_008',
  SIGNATURE_INVALID: 'SIGN_001',
  DOCUMENT_TAMPERED: 'SIGN_002',
  HASH_MISMATCH: 'SIGN_003',
  INVALID_SIGNATURE_FORMAT: 'SIGN_004',
  SIGNATURE_ALGORITHM_NOT_ALLOWED: 'SIGN_005',
  VALIDATION_TIMEOUT: 'VALID_001',
  VALIDATION_FAILED: 'VALID_002',
  POLICY_VALIDATION_FAILED: 'VALID_003',
  FILE_TOO_LARGE: 'SYS_001',
  UNSUPPORTED_FORMAT: 'SYS_002',
  INTERNAL_ERROR: 'SYS_003',
} as const;

export const ALLOWED_SIGNATURE_ALGORITHMS = [
  'SHA256withRSA',
  'SHA384withRSA',
  'SHA512withRSA',
  'SHA256withECDSA',
  'SHA384withECDSA',
  'SHA512withECDSA',
  'SHA-256withRSA',
  'SHA-384withRSA',
  'SHA-512withRSA',
  'SHA-256withECDSA',
  'SHA-384withECDSA',
  'SHA-512withECDSA',
  'sha256WithRSAEncryption',
  'sha384WithRSAEncryption',
  'sha512WithRSAEncryption',
  'sha256WithECDSAEncryption',
  'sha384WithECDSAEncryption',
  'sha512WithECDSAEncryption'
] as const;

export const ALLOWED_HASH_ALGORITHMS = [
  'SHA-256',
  'SHA-384',
  'SHA-512',
] as const;

export const MIN_KEY_SIZES = {
  RSA: 2048,
  ECDSA: 256,
} as const;

export const VALIDATION_PATTERNS = {
  CPF: /^\d{3}\.\d{3}\.\d{3}-\d{2}$|^\d{11}$/,
  CNPJ: /^\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}$|^\d{14}$/,
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
} as const;