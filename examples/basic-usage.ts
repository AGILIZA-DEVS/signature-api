import { DocumentSigner, SignatureOptions } from '../src';
import { readFileSync } from 'fs';

// Exemplo básico de uso
async function basicExample() {
  const options: SignatureOptions = {
    certificate: readFileSync('./path/to/certificate.pem'),
    privateKey: readFileSync('./path/to/private-key.pem'),
    password: 'your-key-password', // opcional
    algorithm: 'RSA-SHA256'
  };

  const signer = new DocumentSigner(options);

  const document = {
    document: readFileSync('./document.pdf'),
    format: 'pdf',
    name: 'contract.pdf'
  };

  try {
    const result = await signer.signDocument(document);
    console.log('Documento assinado com sucesso:', {
      timestamp: result.timestamp,
      algorithm: result.signature.algorithm,
      isValid: result.signature.isValid
    });

    // Salvar documento assinado
    // writeFileSync('./signed-document.pdf', result.signedDocument);

  } catch (error) {
    console.error('Erro ao assinar documento:', error);
  }
}

// Exemplo de verificação de assinatura
async function verificationExample() {
  const options: SignatureOptions = {
    certificate: readFileSync('./path/to/certificate.pem'),
    privateKey: readFileSync('./path/to/private-key.pem')
  };

  const signer = new DocumentSigner(options);
  const signedDocument = readFileSync('./signed-document.pdf');

  try {
    const isValid = await signer.verifySignature(signedDocument);
    console.log('Assinatura válida:', isValid);

    const signatureInfo = await signer.getSignatureInfo(signedDocument);
    console.log('Informações da assinatura:', signatureInfo);
  } catch (error) {
    console.error('Erro ao verificar assinatura:', error);
  }
}

// basicExample();
// verificationExample();