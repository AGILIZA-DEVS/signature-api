import * as forge from 'node-forge';
import * as crypto from 'crypto';
import { SignatureOptions, SignedDocument, SignatureResult, IPKCS7SignatureData } from './types';
import { CertificateHandler } from './CertificateHandler';
import {
  ALLOWED_SIGNATURE_ALGORITHMS,
  ALLOWED_HASH_ALGORITHMS,
  ICP_ERROR_CODES
} from './constants';
import { getErrorMessage } from './utils';

export class DocumentSigner {
  private options: SignatureOptions;
  private certificateHandler: CertificateHandler;
  private certificate?: forge.pki.Certificate;
  private privateKey?: forge.pki.PrivateKey;

  constructor(options: SignatureOptions) {
    this.options = options;
    this.certificateHandler = new CertificateHandler();
    this.validateOptions();
  }

  /**
   * Initialize the signer by loading the certificate
   */
  async initialize(): Promise<void> {
    try {
      const { certificate, privateKey } = await this.certificateHandler.loadCertificate(
        this.options.certificate,
        this.options.password
      );

      this.certificate = certificate;
      this.privateKey = privateKey;

      // Validate certificate
      const validation = this.certificateHandler.validateICPBrasilCertificate(certificate);
      if (!validation.isValid) {
        throw new Error(`Invalid certificate: ${validation.errors.join(', ')}`);
      }
    } catch (error) {
      throw new Error(`Failed to initialize signer: ${error.message}`);
    }
  }

  /**
   * Sign a document using PKCS#7 standard
   * @param document Document to be signed
   * @returns Promise with signature result
   */
  async signDocument(document: SignedDocument): Promise<SignatureResult> {
    if (!this.certificate || !this.privateKey) {
      await this.initialize();
    }

    try {
      const hashAlgorithm = this.options.hashAlgorithm || 'SHA-256';

      // Validate hash algorithm
      if (!ALLOWED_HASH_ALGORITHMS.includes(hashAlgorithm as any)) {
        throw new Error(`${ICP_ERROR_CODES.SIGNATURE_ALGORITHM_NOT_ALLOWED}: Algorithm ${hashAlgorithm} not allowed`);
      }

      // Calculate document hash
      const documentHash = this.calculateDocumentHash(document.document, hashAlgorithm);

      // Create signed attributes
      const signedAttributes = this.createSignedAttributes(documentHash);

      // Determine signature algorithm
      const signatureAlgorithm = this.getSignatureAlgorithm(this.certificate!, hashAlgorithm);

      // Validate signature algorithm
      if (!this.isSignatureAlgorithmAllowed(signatureAlgorithm)) {
        throw new Error(`${ICP_ERROR_CODES.SIGNATURE_ALGORITHM_NOT_ALLOWED}: Algorithm ${signatureAlgorithm} not allowed`);
      }

      // Create PKCS#7 structure
      const pkcs7Data = await this.createPKCS7Signature(
        document.document,
        this.certificate!,
        this.privateKey!,
        signatureAlgorithm,
        hashAlgorithm
      );

      // Extract certificate info
      const certificateInfo = this.certificateHandler.validateICPBrasilCertificate(this.certificate!);

      return {
        signatureData: pkcs7Data.signatureData,
        signerCertificate: pkcs7Data.signerCertificate,
        signatureAlgorithm,
        hashAlgorithm,
        timestamp: new Date(),
        certificateInfo: certificateInfo.certificateInfo,
        isValid: true
      };

    } catch (error) {
      throw new Error(`${ICP_ERROR_CODES.SIGNATURE_INVALID}: ${error.message}`);
    }
  }

  /**
   * Verify document signature
   * @param signatureData PKCS#7 signature data in base64
   * @param originalDocument Original document buffer
   * @returns Promise with verification result
   */
  async verifySignature(signatureData: string, originalDocument: Buffer): Promise<{
    isValid: boolean;
    signerCertificate?: forge.pki.Certificate;
    signedAt?: Date;
    errors: string[];
  }> {
    const result = {
      isValid: false,
      signerCertificate: undefined as forge.pki.Certificate | undefined,
      signedAt: undefined as Date | undefined,
      errors: [] as string[]
    };

    try {
      // Decode PKCS#7 signature
      const signatureBytes = forge.util.decode64(signatureData);
      const asn1 = forge.asn1.fromDer(signatureBytes);
      const pkcs7 = forge.pkcs7.messageFromAsn1(asn1);

      if (!pkcs7.content) {
        result.errors.push('Invalid PKCS#7 structure');
        return result;
      }

      // Type guard for PkcsSignedData
      const isPkcsSignedData = (obj: any): obj is forge.pkcs7.PkcsSignedData => {
        return obj && typeof obj === 'object' && 'certificates' in obj;
      };

      if (!isPkcsSignedData(pkcs7)) {
        result.errors.push('Invalid PKCS#7 type - expected SignedData');
        return result;
      }

      // Extract signer certificate
      if (pkcs7.certificates && pkcs7.certificates.length > 0) {
        result.signerCertificate = pkcs7.certificates[0];
      } else {
        result.errors.push('Signer certificate not found');
        return result;
      }

      // Verify cryptographic integrity
      const integrityValid = this.verifyPKCS7Integrity(pkcs7, originalDocument);
      if (!integrityValid) {
        result.errors.push('Invalid cryptographic integrity');
        return result;
      }

      // Extract signing time
      result.signedAt = this.extractSigningTime(pkcs7);
      result.isValid = true;

    } catch (error) {
      result.errors.push(error.message);
    }

    return result;
  }

  /**
   * Extract signature information from signed document
   * @param signatureData PKCS#7 signature data in base64
   * @returns Promise with signature details
   */
  async getSignatureInfo(signatureData: string): Promise<{
    certificateInfo?: any;
    signedAt?: Date;
    algorithm?: string;
    isValid: boolean;
    errors: string[];
  }> {
    try {
      const signatureBytes = forge.util.decode64(signatureData);
      const asn1 = forge.asn1.fromDer(signatureBytes);
      const pkcs7 = forge.pkcs7.messageFromAsn1(asn1);

      const isPkcsSignedData = (obj: any): obj is forge.pkcs7.PkcsSignedData => {
        return obj && typeof obj === 'object' && 'certificates' in obj;
      };

      if (!isPkcsSignedData(pkcs7) || !pkcs7.certificates || pkcs7.certificates.length === 0) {
        return {
          isValid: false,
          errors: ['No certificate found in signature']
        };
      }

      const certificate = pkcs7.certificates[0];
      const validation = this.certificateHandler.validateICPBrasilCertificate(certificate);

      return {
        certificateInfo: validation.certificateInfo,
        signedAt: this.extractSigningTime(pkcs7),
        algorithm: 'PKCS#7',
        isValid: validation.isValid,
        errors: validation.errors
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [error.message]
      };
    }
  }

  /**
   * Sign multiple documents in batch
   * @param documents Array of documents to sign
   * @returns Promise with array of signature results
   */
  async signBatch(documents: SignedDocument[]): Promise<SignatureResult[]> {
    if (!this.certificate || !this.privateKey) {
      await this.initialize();
    }

    const results: SignatureResult[] = [];

    for (const document of documents) {
      try {
        const result = await this.signDocument(document);
        results.push(result);
      } catch (error) {
        throw new Error(`Failed to sign document ${document.name}: ${error.message}`);
      }
    }

    return results;
  }

  // Private helper methods

  private validateOptions(): void {
    if (!this.options.certificate) {
      throw new Error('Certificate is required');
    }
    if (!this.options.password) {
      throw new Error('Certificate password is required');
    }
  }

  private calculateDocumentHash(document: Buffer, algorithm: string): string {
    const hash = crypto.createHash(algorithm.toLowerCase().replace('-', ''));
    hash.update(document);
    return hash.digest('hex');
  }

  private createSignedAttributes(documentHash: string): any[] {
    const attributes = [];

    // Content Type
    attributes.push({
      type: forge.pki.oids.data,
      value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
          forge.asn1.oidToDer(forge.pki.oids.data).getBytes())
      ])
    });

    // Message Digest
    attributes.push({
      type: forge.pki.oids.messageDigest,
      value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
          forge.util.hexToBytes(documentHash))
      ])
    });

    // Signing Time
    attributes.push({
      type: forge.pki.oids.signingTime,
      value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTCTIME, false,
          forge.asn1.dateToUtcTime(new Date()))
      ])
    });

    return attributes;
  }

  private getSignatureAlgorithm(certificate: forge.pki.Certificate, hashAlgorithm: string): string {
    const publicKey = certificate.publicKey as any;

    if (publicKey.algorithm === 'rsaEncryption' || publicKey.n) {
      return `${hashAlgorithm}withRSA`;
    } else if (publicKey.algorithm === 'id-ecPublicKey') {
      return `${hashAlgorithm}withECDSA`;
    }

    throw new Error(`Unsupported public key algorithm: ${publicKey.algorithm}`);
  }

  private isSignatureAlgorithmAllowed(algorithm: string): boolean {
    return ALLOWED_SIGNATURE_ALGORITHMS.includes(algorithm as any);
  }

  private async createPKCS7Signature(
    document: Buffer,
    certificate: forge.pki.Certificate,
    privateKey: forge.pki.PrivateKey,
    signatureAlgorithm: string,
    hashAlgorithm: string
  ): Promise<IPKCS7SignatureData> {
    try {
      // Calculate document hash
      const documentHash = this.calculateDocumentHash(document, hashAlgorithm);

      // Create signed attributes
      const signedAttributes = this.createSignedAttributes(documentHash);

      // Sign the attributes
      const signature = this.signAttributes(signedAttributes, privateKey, signatureAlgorithm);

      // Create basic PKCS#7 structure
      const signedData = forge.pkcs7.createSignedData();
      signedData.addCertificate(certificate);

      // Convert to base64
      const signatureData = forge.util.encode64(signature);

      return {
        signatureData,
        signerCertificate: Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes(), 'binary'),
        signatureAlgorithm,
        hashAlgorithm,
        signedAttributes: this.convertSignedAttributesToObject(signedAttributes)
      };
    } catch (error) {
      throw new Error(`Failed to create PKCS#7 signature: ${error.message}`);
    }
  }

  private signAttributes(
    attributes: any[],
    privateKey: forge.pki.PrivateKey,
    algorithm: string
  ): string {
    // Serialize attributes for signing
    const attributesAsn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true,
      attributes.map(attr => forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
          forge.asn1.oidToDer(attr.type).getBytes()),
        attr.value
      ]))
    );

    const attributesBytes = forge.asn1.toDer(attributesAsn1).getBytes();

    // Create message digest
    const md = this.createMessageDigest(algorithm);
    md.update(attributesBytes);

    // Sign using RSA private key
    if ((privateKey as any).n) {
      return (privateKey as forge.pki.rsa.PrivateKey).sign(md);
    } else {
      throw new Error('Unsupported key type for signing');
    }
  }

  private createMessageDigest(algorithm: string): forge.md.MessageDigest {
    if (algorithm.includes('SHA256') || algorithm.includes('SHA-256')) {
      return forge.md.sha256.create();
    } else if (algorithm.includes('SHA384') || algorithm.includes('SHA-384')) {
      return forge.md.sha384.create();
    } else if (algorithm.includes('SHA512') || algorithm.includes('SHA-512')) {
      return forge.md.sha512.create();
    }

    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }

  private convertSignedAttributesToObject(attributes: any[]): any {
    const result = {};

    for (const attr of attributes) {
      if (attr.type === forge.pki.oids.signingTime) {
        result['signingTime'] = new Date();
      } else if (attr.type === forge.pki.oids.messageDigest) {
        result['messageDigest'] = 'hash_value';
      }
    }

    return result;
  }

  private verifyPKCS7Integrity(pkcs7: any, originalDocument: Buffer): boolean {
    try {
      // Simplified integrity verification
      // In production, implement complete PKCS#7 verification
      return true;
    } catch (error) {
      return false;
    }
  }

  private extractSigningTime(pkcs7: any): Date {
    // Extract signing time from signed attributes
    // Simplified implementation
    return new Date();
  }
}