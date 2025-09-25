import { DocumentSigner, SignatureOptions } from '../src';
import { readFileSync } from 'fs';

// Exemplo de assinatura em lote
async function batchSigningExample() {
  const options: SignatureOptions = {
    certificate: readFileSync('./path/to/certificate.pem'),
    privateKey: readFileSync('./path/to/private-key.pem'),
    algorithm: 'RSA-SHA256',
    metadata: {
      signer: 'João Silva',
      organization: 'Agiliza Corp'
    }
  };

  const signer = new DocumentSigner(options);

  const documents = [
    {
      document: readFileSync('./contract1.pdf'),
      format: 'pdf',
      name: 'contract1.pdf'
    },
    {
      document: readFileSync('./contract2.pdf'),
      format: 'pdf',
      name: 'contract2.pdf'
    },
    {
      document: readFileSync('./agreement.docx'),
      format: 'docx',
      name: 'agreement.docx'
    }
  ];

  try {
    console.log('Iniciando assinatura em lote...');
    const results = await signer.signBatch(documents);

    results.forEach((result, index) => {
      console.log(`Documento ${documents[index]!.name}:`, {
        timestamp: result.timestamp,
        size: result.signedDocument.length,
        isValid: result.signature.isValid
      });

      // Salvar cada documento assinado
      // writeFileSync(`./signed-${documents[index]!.name}`, result.signedDocument);
    });

    console.log('Assinatura em lote concluída com sucesso!');
  } catch (error) {
    console.error('Erro na assinatura em lote:', error);
  }
}

// batchSigningExample();