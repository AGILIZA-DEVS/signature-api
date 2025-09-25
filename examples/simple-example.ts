import { DocumentSigner } from '../src';
import { readFileSync } from 'fs';

async function simpleExample() {
  try {
    // Initialize signer with certificate
    const signer = new DocumentSigner({
      certificate: readFileSync('./path/to/certificate.p12'),
      password: 'certificate-password',
      hashAlgorithm: 'SHA-256'
    });

    // Initialize the signer (loads and validates certificate)
    await signer.initialize();

    // Prepare document
    const document = {
      document: readFileSync('./document.pdf'),
      format: 'pdf',
      name: 'contract.pdf'
    };

    // Sign document
    const result = await signer.signDocument(document);

    console.log('Document signed successfully:', {
      timestamp: result.timestamp,
      algorithm: result.signatureAlgorithm,
      isValid: result.isValid,
      certificateSubject: result.certificateInfo.subject
    });

    // Verify signature
    const verification = await signer.verifySignature(
      result.signatureData,
      document.document
    );

    console.log('Signature verification:', verification.isValid);

  } catch (error) {
    console.error('Error:', error);
  }
}

// Uncomment to run
// simpleExample();