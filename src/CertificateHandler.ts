import * as forge from 'node-forge';
import * as crypto from 'crypto';
import {
  ICertificateInfo,
  IValidationResult
} from './types';
import {
  ICP_BRASIL_OIDS,
  CRL_URLS,
  ICP_ERROR_CODES,
  MIN_KEY_SIZES,
  VALIDATION_PATTERNS
} from './constants';

export class CertificateHandler {
  private crlCache = new Map<string, { data: any; timestamp: number }>();

  /**
   * Load PKCS#12 certificate (.p12/.pfx)
   * @param p12Buffer Buffer from .p12/.pfx file
   * @param password Certificate password
   * @returns Certificate and private key
   */
  async loadCertificate(p12Buffer: Buffer, password: string): Promise<{
    certificate: forge.pki.Certificate;
    privateKey: forge.pki.PrivateKey;
    certificateChain: forge.pki.Certificate[];
  }> {
    try {
      const asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
      const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

      const bags = p12.getBags({
        bagType: forge.pki.oids.certBag
      });

      const keyBags = p12.getBags({
        bagType: forge.pki.oids.pkcs8ShroudedKeyBag
      });

      if (!bags[forge.pki.oids.certBag] || bags[forge.pki.oids.certBag].length === 0) {
        throw new Error('Certificate not found in PKCS#12 file');
      }

      if (!keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || keyBags[forge.pki.oids.pkcs8ShroudedKeyBag].length === 0) {
        throw new Error('Private key not found in PKCS#12 file');
      }

      const certificate = bags[forge.pki.oids.certBag][0].cert as forge.pki.Certificate;
      const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key as forge.pki.PrivateKey;

      const certificateChain: forge.pki.Certificate[] = [];
      for (const bag of bags[forge.pki.oids.certBag]) {
        if (bag.cert) {
          certificateChain.push(bag.cert as forge.pki.Certificate);
        }
      }

      return { certificate, privateKey, certificateChain };
    } catch (error) {
      throw new Error(`${ICP_ERROR_CODES.INVALID_CERTIFICATE}: ${error.message}`);
    }
  }

  /**
   * Validate if it's a valid ICP-Brasil certificate
   * @param certificate Certificate to validate
   * @returns Validation result
   */
  validateICPBrasilCertificate(certificate: forge.pki.Certificate): {
    isValid: boolean;
    isICPBrasil: boolean;
    certificateInfo: ICertificateInfo;
    errors: string[];
  } {
    const result = {
      isValid: true,
      isICPBrasil: false,
      certificateInfo: this.extractCertificateInfo(certificate),
      errors: [] as string[]
    };

    try {
      // Validate if it's ICP-Brasil certificate
      result.isICPBrasil = this.isICPBrasilCertificate(certificate);

      if (!result.isICPBrasil) {
        result.isValid = false;
        result.errors.push(ICP_ERROR_CODES.CERTIFICATE_NOT_ICP_BRASIL);
      }

      // Validate time validity
      const timeValidation = this.validateCertificateTime(certificate);
      if (!timeValidation.isValid) {
        result.isValid = false;
        result.errors.push(...timeValidation.errors);
      }

      // Validate policies
      const policyValidation = this.validateICPBrasilPolicies(certificate);
      if (!policyValidation.isCompliant) {
        result.isValid = false;
        result.errors.push(...policyValidation.errors);
      }

      // Validate key size
      const keyValidation = this.validateKeySize(certificate);
      if (!keyValidation.isValid) {
        result.isValid = false;
        result.errors.push(keyValidation.error!);
      }

    } catch (error) {
      result.isValid = false;
      result.errors.push(error.message);
    }

    return result;
  }

  /**
   * Extract CPF/CNPJ from ICP-Brasil certificate
   * @param certificate Certificate
   * @returns CPF/CNPJ or null if not found
   */
  extractCpfCnpj(certificate: forge.pki.Certificate): string | null {
    try {
      const extensions = certificate.extensions;

      for (const extension of extensions) {
        if (extension.id === ICP_BRASIL_OIDS.CPF || extension.id === ICP_BRASIL_OIDS.CNPJ) {
          const asn1 = forge.asn1.fromDer(extension.value);
          return this.extractIdentifierFromASN1(asn1);
        }
      }

      const sanExtension = certificate.extensions.find(ext => ext.name === 'subjectAltName');
      if (sanExtension && sanExtension.altNames) {
        for (const altName of sanExtension.altNames) {
          if (altName.type === 0) {
            const identifier = this.parseOtherNameForIdentifier(altName);
            if (identifier) return identifier;
          }
        }
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  // Private helper methods

  private extractCertificateInfo(certificate: forge.pki.Certificate): ICertificateInfo {
    return {
      subject: certificate.subject.getField('CN')?.value || '',
      issuer: certificate.issuer.getField('CN')?.value || '',
      serialNumber: certificate.serialNumber,
      validity: {
        notBefore: certificate.validity.notBefore,
        notAfter: certificate.validity.notAfter,
      },
      cpfCnpj: this.extractCpfCnpj(certificate),
      keyUsage: this.extractKeyUsage(certificate),
      extendedKeyUsage: this.extractExtendedKeyUsage(certificate),
      policies: this.extractCertificatePolicies(certificate),
      publicKey: {
        algorithm: this.getPublicKeyAlgorithm(certificate),
        size: this.getPublicKeySize(certificate),
      },
    };
  }

  private isICPBrasilCertificate(certificate: forge.pki.Certificate): boolean {
    const policies = this.extractCertificatePolicies(certificate);
    const hasA1Policy = policies.includes(ICP_BRASIL_OIDS.POLICY_A1);
    const hasA3Policy = policies.includes(ICP_BRASIL_OIDS.POLICY_A3);
    const hasA4Policy = policies.includes(ICP_BRASIL_OIDS.POLICY_A4);
    const hasSyngularPolicy = policies.includes(ICP_BRASIL_OIDS.POLICY_SYNGULAR);

    const icpPolicies = Object.values(ICP_BRASIL_OIDS).filter(oid =>
      oid.startsWith('2.16.76.1.2.1.')
    );

    const hasPolicyMatch = policies.some(policy => icpPolicies.includes(policy as any));
    const hasCharacteristics = this.hasICPBrasilCharacteristics(certificate);
    const hasA1Characteristics = this.hasA1Characteristics(certificate);
    const hasFlexibleValidation = this.hasFlexibleICPValidation(certificate);

    return hasPolicyMatch || hasCharacteristics || hasA1Characteristics || hasFlexibleValidation;
  }

  private hasA1Characteristics(certificate: forge.pki.Certificate): boolean {
    try {
      const keyUsageExt = certificate.extensions.find(ext => ext.name === 'keyUsage');
      const hasDigitalSignature = keyUsageExt && (keyUsageExt as any).digitalSignature;
      const hasNonRepudiation = keyUsageExt && (keyUsageExt as any).nonRepudiation;

      const hasRequiredUsage = hasDigitalSignature || hasNonRepudiation;

      const hasBrazilianExtensions = certificate.extensions.some(ext =>
        ext.id && ext.id.startsWith('2.16.76.1')
      );

      const issuer = certificate.issuer.getField('CN')?.value || '';
      const brazilianIssuers = [
        'certisign', 'serasa', 'serpro', 'valid', 'safenet', 'soluti',
        'ac ', 'autoridade certificadora', 'brasil', 'receita', 'gov',
        'syngular', 'syngularid'
      ];

      const hasBrazilianIssuer = brazilianIssuers.some(issuerName =>
        issuer.toLowerCase().includes(issuerName)
      );

      return hasRequiredUsage && (hasBrazilianIssuer || hasBrazilianExtensions);
    } catch (error) {
      return false;
    }
  }

  private hasFlexibleICPValidation(certificate: forge.pki.Certificate): boolean {
    try {
      const issuer = certificate.issuer.getField('CN')?.value || '';
      const subject = certificate.subject.getField('CN')?.value || '';

      const icpIndicators = [
        'brasil', 'serpro', 'certisign', 'serasa', 'valid', 'safenet',
        'ac ', 'autoridade certificadora', 'icp', 'iti', 'soluti',
        'caixa', 'banco', 'receita', 'gov.br', 'syngular', 'syngularid'
      ];

      const issuerLower = issuer.toLowerCase();
      const subjectLower = subject.toLowerCase();

      const hasIcpIndicator = icpIndicators.some(indicator =>
        issuerLower.includes(indicator) || subjectLower.includes(indicator)
      );

      const hasBrazilianOid = certificate.extensions.some(ext => {
        if (ext.id && ext.id.startsWith('2.16.76.1')) {
          return true;
        }
        return false;
      });

      const keyUsageExt = certificate.extensions.find(ext => ext.name === 'keyUsage');
      const hasDigitalSignature = keyUsageExt && (keyUsageExt as any).digitalSignature;

      const score = Number(hasIcpIndicator) + Number(hasBrazilianOid) + Number(hasDigitalSignature);
      return score >= 1;
    } catch (error) {
      return false;
    }
  }

  private validateCertificateTime(certificate: forge.pki.Certificate) {
    const now = new Date();
    const isValid = now >= certificate.validity.notBefore && now <= certificate.validity.notAfter;

    return {
      isValid,
      currentTime: now,
      errors: isValid ? [] : ['Certificate outside validity period']
    };
  }

  private validateICPBrasilPolicies(certificate: forge.pki.Certificate) {
    const policies = this.extractCertificatePolicies(certificate);
    const icpPolicies = policies.filter(policy =>
      Object.values(ICP_BRASIL_OIDS).includes(policy as any)
    );

    return {
      isCompliant: icpPolicies.length > 0,
      policies: icpPolicies,
      errors: icpPolicies.length === 0 ? ['No ICP-Brasil policy found'] : []
    };
  }

  private validateKeySize(certificate: forge.pki.Certificate) {
    const algorithm = this.getPublicKeyAlgorithm(certificate);
    const size = this.getPublicKeySize(certificate);
    const minSize = MIN_KEY_SIZES[algorithm as keyof typeof MIN_KEY_SIZES];

    if (!minSize || size < minSize) {
      return {
        isValid: false,
        error: `Key size ${size} bits insufficient for ${algorithm} (minimum: ${minSize} bits)`
      };
    }

    return { isValid: true, error: null };
  }

  private extractKeyUsage(certificate: forge.pki.Certificate): string[] {
    const extension = certificate.extensions.find(ext => ext.name === 'keyUsage');
    return extension ? Object.keys(extension).filter(key => extension[key] === true) : [];
  }

  private extractExtendedKeyUsage(certificate: forge.pki.Certificate): string[] {
    const extension = certificate.extensions.find(ext => ext.name === 'extKeyUsage');
    return extension?.serverAuth ? ['serverAuth'] : [];
  }

  private extractCertificatePolicies(certificate: forge.pki.Certificate): string[] {
    const policies: string[] = [];

    try {
      for (const extension of certificate.extensions) {
        if (extension.id === ICP_BRASIL_OIDS.CERTIFICATE_POLICIES || extension.id === '2.5.29.32') {
          try {
            const asn1 = forge.asn1.fromDer(extension.value);
            this.extractPoliciesFromASN1(asn1, policies);
          } catch (error) {
            // Ignore parsing errors
          }
        }

        if (extension.name === 'certificatePolicies' && (extension as any).value) {
          const policyValues = (extension as any).value;
          if (Array.isArray(policyValues)) {
            for (const policyInfo of policyValues) {
              if (policyInfo.policyIdentifier) {
                policies.push(policyInfo.policyIdentifier);
              }
            }
          }
        }
      }

      // Fallback for A1 certificates
      if (policies.length === 0) {
        if (this.hasICPBrasilCharacteristics(certificate)) {
          policies.push(ICP_BRASIL_OIDS.POLICY_A1);
        } else if (this.hasA1Characteristics(certificate)) {
          policies.push(ICP_BRASIL_OIDS.POLICY_A1);
        } else if (this.hasMinimalBrazilianCharacteristics(certificate)) {
          policies.push(ICP_BRASIL_OIDS.POLICY_A1);
        }
      }
    } catch (error) {
      // Ignore errors
    }

    return policies;
  }

  private getPublicKeyAlgorithm(certificate: forge.pki.Certificate): string {
    return (certificate.publicKey as any).algorithm || 'RSA';
  }

  private getPublicKeySize(certificate: forge.pki.Certificate): number {
    const publicKey = certificate.publicKey as any;
    if (publicKey.n) {
      return publicKey.n.bitLength();
    }
    return 256;
  }

  private extractPoliciesFromASN1(asn1: forge.asn1.Asn1, policies: string[]): void {
    try {
      if (asn1.type === forge.asn1.Type.SEQUENCE && asn1.value) {
        for (const item of asn1.value as forge.asn1.Asn1[]) {
          if (item.type === forge.asn1.Type.SEQUENCE && item.value) {
            const sequence = item.value as forge.asn1.Asn1[];
            if (sequence.length > 0 && sequence[0].type === forge.asn1.Type.OID) {
              const oid = forge.asn1.derToOid(sequence[0].value as string);
              if (oid) {
                policies.push(oid);
              }
            }
          }
        }
      }
    } catch (error) {
      // Ignore parsing errors
    }
  }

  private hasICPBrasilCharacteristics(certificate: forge.pki.Certificate): boolean {
    try {
      const issuer = certificate.issuer.getField('CN')?.value || '';

      const icpIssuers = [
        'AC CERTISIGN',
        'AC SERASA',
        'AC SERPRO',
        'AC VALID',
        'AC SAFENET',
        'ICP-Brasil',
        'ITI',
        'Autoridade Certificadora'
      ];

      const hasIcpIssuer = icpIssuers.some(issuerName =>
        issuer.toUpperCase().includes(issuerName.toUpperCase())
      );

      const hasBrazilianOids = certificate.extensions.some(ext =>
        ext.id && ext.id.startsWith('2.16.76.1')
      );

      const hasCpfCnpjExtension = certificate.extensions.some(ext =>
        ext.id === ICP_BRASIL_OIDS.CPF || ext.id === ICP_BRASIL_OIDS.CNPJ
      );

      return hasIcpIssuer || hasBrazilianOids || hasCpfCnpjExtension;
    } catch (error) {
      return false;
    }
  }

  private extractIdentifierFromASN1(asn1: forge.asn1.Asn1): string | null {
    try {
      if (asn1.type === forge.asn1.Type.SEQUENCE && asn1.value) {
        const sequence = asn1.value as forge.asn1.Asn1[];
        for (const item of sequence) {
          if (item.type === forge.asn1.Type.UTF8 ||
              item.type === forge.asn1.Type.PRINTABLESTRING ||
              item.type === forge.asn1.Type.IA5STRING) {
            const value = item.value as string;
            if (this.isValidCpfCnpj(value)) {
              return value;
            }
          }
        }
      }
    } catch (error) {
      // Ignore errors
    }
    return null;
  }

  private isValidCpfCnpj(value: string): boolean {
    if (!value) return false;

    const cleanValue = value.replace(/[^\d]/g, '');

    if (cleanValue.length === 11) {
      return VALIDATION_PATTERNS.CPF.test(value) || /^\d{11}$/.test(cleanValue);
    }

    if (cleanValue.length === 14) {
      return VALIDATION_PATTERNS.CNPJ.test(value) || /^\d{14}$/.test(cleanValue);
    }

    return false;
  }

  private hasMinimalBrazilianCharacteristics(certificate: forge.pki.Certificate): boolean {
    try {
      const issuer = certificate.issuer.getField('CN')?.value || '';
      const subject = certificate.subject.getField('CN')?.value || '';

      const brazilIndicators = ['br', '.br', 'brasil', 'brazil', 'receita', 'cpf', 'cnpj'];

      const hasBrazilIndicator = brazilIndicators.some(indicator => {
        const issuerMatch = issuer.toLowerCase().includes(indicator);
        const subjectMatch = subject.toLowerCase().includes(indicator);
        return issuerMatch || subjectMatch;
      });

      const keyUsageExt = certificate.extensions.find(ext => ext.name === 'keyUsage');
      const canSign = keyUsageExt && (
        (keyUsageExt as any).digitalSignature ||
        (keyUsageExt as any).nonRepudiation
      );

      const extKeyUsageExt = certificate.extensions.find(ext => ext.name === 'extKeyUsage');
      const isNotServerCert = !extKeyUsageExt || !(extKeyUsageExt as any).serverAuth;

      return (hasBrazilIndicator || canSign) && isNotServerCert;
    } catch (error) {
      return false;
    }
  }

  private parseOtherNameForIdentifier(altName: any): string | null {
    try {
      if (altName.value && typeof altName.value === 'string') {
        if (this.isValidCpfCnpj(altName.value)) {
          return altName.value;
        }
      }

      if (altName.value && altName.value.length > 0) {
        try {
          const asn1 = forge.asn1.fromDer(altName.value);
          return this.extractIdentifierFromASN1(asn1);
        } catch (error) {
          // Ignore ASN.1 parsing errors
        }
      }

      if (altName.typeId) {
        const typeId = altName.typeId;
        if (typeId === ICP_BRASIL_OIDS.CPF || typeId === ICP_BRASIL_OIDS.CNPJ) {
          if (altName.value && typeof altName.value === 'string') {
            return altName.value;
          }
        }
      }

      return null;
    } catch (error) {
      return null;
    }
  }
}