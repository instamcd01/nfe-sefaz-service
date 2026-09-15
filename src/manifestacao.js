// Manifestação do Destinatário ("Ciência da Operação", tpEvento 210210) —
// a Sefaz só libera o documento completo pra consulta via consChNFe
// depois que o destinatário registra essa manifestação (achado real
// 15/09, confirmado pela Nota Técnica 2014.002 oficial: "documentos
// fiscais... só ficam disponíveis se o destinatário der ciência da
// operação, confirmação ou desconhecimento" — exceto cancelamento).
// Referência de implementação: github.com/lucashpmelo/node-mde (MIT) —
// não usado como dependência direta (dependências travadas em versões
// vulneráveis, ver package.json), só como conferência da estrutura.

require('./xmldom-fix');
const https = require('https');
const { SignedXml } = require('xml-crypto');

const SEFAZ_HOSTNAME = 'www1.nfe.fazenda.gov.br';
const SEFAZ_PATH = '/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx';
const SOAP_ACTION = 'http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento';

const TP_EVENTO_CIENCIA = '210210';
const DESC_EVENTO_CIENCIA = 'Ciencia da Operacao';

/** "2026-09-15T16:38:00-03:00" — Sefaz espera hora local de Brasília; o
 * Brasil não observa horário de verão desde 2019, -03:00 é seguro fixo. */
function dhEventoAgora() {
  const agora = new Date();
  const partes = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(agora);
  const p = Object.fromEntries(partes.map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}-03:00`;
}

function montarEventoXml({ chave, cnpj, cOrgao, tpAmb, nSeqEvento = 1 }) {
  const dhEvento = dhEventoAgora();
  const nSeq = String(nSeqEvento).padStart(2, '0');
  const id = `ID${TP_EVENTO_CIENCIA}${chave}${nSeq}`;

  const infEvento =
    `<infEvento Id="${id}">` +
    `<cOrgao>${cOrgao}</cOrgao>` +
    `<tpAmb>${tpAmb}</tpAmb>` +
    `<CNPJ>${cnpj}</CNPJ>` +
    `<chNFe>${chave}</chNFe>` +
    `<dhEvento>${dhEvento}</dhEvento>` +
    `<tpEvento>${TP_EVENTO_CIENCIA}</tpEvento>` +
    `<nSeqEvento>${nSeqEvento}</nSeqEvento>` +
    `<verEvento>1.00</verEvento>` +
    `<detEvento versao="1.00">` +
    `<descEvento>${DESC_EVENTO_CIENCIA}</descEvento>` +
    `</detEvento>` +
    `</infEvento>`;

  return { xml: `<evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">${infEvento}</evento>`, id };
}

function assinarEvento(xml, cert, key) {
  const sig = new SignedXml({ privateKey: key, publicCert: cert });
  sig.addReference({
    xpath: "//*[local-name(.)='infEvento']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    ],
    digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
  });
  sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='infEvento']", action: 'after' },
  });
  return sig.getSignedXml();
}

function montarSoapEnvEvento(eventoAssinado) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
      <envEvento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
        <idLote>1</idLote>
        ${eventoAssinado}
      </envEvento>
    </nfeDadosMsg>
  </soap12:Body>
</soap12:Envelope>`;
}

function postSoap(cert, key, soapBody) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: SEFAZ_HOSTNAME,
        path: SEFAZ_PATH,
        method: 'POST',
        cert,
        key,
        headers: {
          'Content-Type': `application/soap+xml; charset=utf-8; action="${SOAP_ACTION}"`,
          'Content-Length': Buffer.byteLength(soapBody),
        },
        timeout: 25000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ statusCode: res.statusCode, corpo: Buffer.concat(chunks).toString('utf-8') }));
      },
    );
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout conectando na Sefaz (evento).')); });
    req.on('error', reject);
    req.write(soapBody);
    req.end();
  });
}

function extrairTag(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i'));
  return m ? m[1] : null;
}

/** A resposta tem cStat/xMotivo DUAS vezes — um do lote (retEnvEvento,
 * ex: 128 "Lote processado") e outro do evento em si (dentro de
 * infEvento, ex: 135 "Evento registrado") — o que importa é o de dentro
 * de infEvento, não o primeiro que aparece no documento (achado real
 * 15/09: extrairTag simples pegava o do lote por engano, reportando
 * `ok:false` mesmo quando o evento tinha sido aceito de verdade). */
function extrairTagDeInfEvento(xml, tag) {
  const bloco = xml.match(/<infEvento[^>]*>([\s\S]*?)<\/infEvento>/i);
  if (!bloco) return null;
  return extrairTag(bloco[1], tag);
}

/** Códigos que significam "a manifestação existe/foi aceita agora ou já
 * existia antes" — em qualquer um desses casos é seguro seguir pra
 * consulta do documento completo. Fora dessa lista, é erro de verdade. */
const CSTAT_MANIFESTACAO_OK = new Set([
  '135', // Evento registrado e vinculado a NF-e
  '136', // Evento registrado, mas não vinculado a NF-e (ainda aceitavel — o registro em si existe)
  '573', // Rejeicao: Duplicidade de evento — já manifestado antes, confirmado empiricamente 15/09
]);

/**
 * Registra "Ciência da Operação" pra essa chave, se ainda não tiver sido
 * registrada. Não lança erro se a Sefaz disser "duplicado" (já
 * manifestado antes por outro caminho) — trata como sucesso, já que o
 * objetivo é só liberar a consulta, não é a primeira vez.
 */
async function manifestarCienciaDaOperacao({ chave, cnpj, cOrgao, tpAmb, cert, key }) {
  const { xml } = montarEventoXml({ chave, cnpj, cOrgao, tpAmb });
  const assinado = assinarEvento(xml, cert, key);
  const soapBody = montarSoapEnvEvento(assinado);

  const resposta = await postSoap(cert, key, soapBody);
  const cStatEvento = extrairTagDeInfEvento(resposta.corpo, 'cStat');
  const xMotivo = extrairTagDeInfEvento(resposta.corpo, 'xMotivo');
  const nProt = extrairTagDeInfEvento(resposta.corpo, 'nProt');

  return {
    ok: CSTAT_MANIFESTACAO_OK.has(cStatEvento),
    cStat: cStatEvento,
    xMotivo,
    nProt,
    statusCode: resposta.statusCode,
    corpoBruto: resposta.corpo,
  };
}

module.exports = { manifestarCienciaDaOperacao };
