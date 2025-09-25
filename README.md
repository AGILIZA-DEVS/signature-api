# @agiliza/signature-api

Uma biblioteca TypeScript para assinatura digital de documentos e verificação de assinaturas.

## Instalação

```bash
npm install @agiliza/signature-api
```

## Uso Básico

```typescript
import { DocumentSigner, SignatureOptions } from '@agiliza/signature-api';
import { readFileSync } from 'fs';

const options: SignatureOptions = {
  certificate: readFileSync('./certificate.p12'), // Arquivo PKCS#12
  password: 'certificate-password',
  hashAlgorithm: 'SHA-256' // opcional, padrão é SHA-256
};

const signer = new DocumentSigner(options);

// Inicializar o assinador (carrega e valida o certificado)
await signer.initialize();

const document = {
  document: readFileSync('./document.pdf'),
  format: 'pdf',
  name: 'contract.pdf'
};

// Assinar documento
const result = await signer.signDocument(document);

// Verificar assinatura
const verification = await signer.verifySignature(
  result.signatureData,
  document.document
);
```

## API

### `DocumentSigner`

#### Constructor
```typescript
new DocumentSigner(options: SignatureOptions)
```

#### Métodos

##### `initialize(): Promise<void>`
Inicializa o assinador carregando e validando o certificado.

##### `signDocument(document: SignedDocument): Promise<SignatureResult>`
Assina um documento usando padrão PKCS#7.

##### `verifySignature(signatureData: string, originalDocument: Buffer): Promise<VerificationResult>`
Verifica se uma assinatura PKCS#7 é válida.

##### `getSignatureInfo(signatureData: string): Promise<SignatureInfo>`
Extrai informações da assinatura PKCS#7.

##### `signBatch(documents: SignedDocument[]): Promise<SignatureResult[]>`
Assina múltiplos documentos em lote.

### Interfaces

#### `SignatureOptions`
```typescript
interface SignatureOptions {
  certificate: Buffer;             // Certificado PKCS#12 (.p12/.pfx)
  password: string;                // Senha do certificado
  hashAlgorithm?: string;          // Algoritmo de hash (padrão: 'SHA-256')
  metadata?: Record<string, any>;  // Metadados adicionais
}
```

#### `SignedDocument`
```typescript
interface SignedDocument {
  document: Buffer;  // Buffer do documento
  format: string;    // Formato (pdf, docx, etc.)
  name: string;      // Nome/identificador do documento
}
```

#### `SignatureResult`
```typescript
interface SignatureResult {
  signatureData: string;           // Dados da assinatura PKCS#7 em base64
  signerCertificate: Buffer;       // Certificado do assinante
  signatureAlgorithm: string;      // Algoritmo de assinatura usado
  hashAlgorithm: string;           // Algoritmo de hash usado
  timestamp: Date;                 // Timestamp da assinatura
  certificateInfo: ICertificateInfo; // Informações do certificado
  isValid: boolean;                // Status de validação
}
```

## Exemplos

Veja a pasta `examples/` para exemplos completos de uso:

- `basic-usage.ts` - Uso básico da biblioteca
- `batch-signing.ts` - Assinatura em lote

## Requisitos

- Node.js >= 16.0.0
- TypeScript (para desenvolvimento)

## Licença

MIT

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request