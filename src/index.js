// Servico dedicado so pra consultar NF-e por chave de acesso no
// webservice oficial NFeDistribuicaoDFe da Sefaz, autenticando com
// certificado digital A1 (mTLS) via o modulo `https` nativo do Node
// (OpenSSL) - existe como servico Node separado (nao dentro da edge
// function Deno do Supabase) porque o Deno tem uma incompatibilidade
// conhecida e sem correcao (rustls, a lib de TLS que ele usa por baixo)
// contra o servidor IIS antigo da Sefaz: toda conexao com certificado
// cliente terminava em "Connection reset by peer", confirmado por
// teste manual com openssl (que funciona) e por uma issue aberta no
// proprio repo do rustls (rustls/rustls#1999, fechada como "not
// planned" - nao ha fix client-side). Node usa OpenSSL nativamente,
// mesma familia que funcionou no teste manual.
//
// Certificado/chave (PEM, sem senha) ficam so no Supabase Vault
// (`nfe_certificado_cert_pem`/`nfe_certificado_key_pem`), lidos via
// `obter_segredo` (RPC SECURITY DEFINER) - nunca em variavel de
// ambiente nem em arquivo neste servico.
//
// A edge function `buscar-nfe-por-chave` do Supabase so repassa a
// chamada pra ca (POST simples, sem certificado nenhum nessa etapa) -
// contrato de resposta identico ao que ja existia: {ok, xml} ou
// {ok:false, erro, mensagem}.

const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { createClient } = require('@supabase/supabase-js');
const { manifestarCienciaDaOperacao } = require('./manifestacao');

const PORT = process.env.PORT || 3000;
const SERVICE_TOKEN = process.env.SERVICE_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const SEFAZ_HOSTNAME = 'www1.nfe.fazenda.gov.br';
const SEFAZ_PATH = '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx';
const SOAP_ACTION = 'http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse';

// Unico empresa hoje (Delivery Pet) - se virar multi-tenant, buscar
// CNPJ/estado da tabela `empresas` em vez de hardcode.
const CNPJ = '52816710000198';
const C_UF_AUTOR = '33'; // RJ - usado na CONSULTA (distDFeInt), diferente do
// evento de manifestacao, que usa cOrgao=91 (Ambiente Nacional) - achado
// real 15/09: usar 33 ali rejeita com cStat 657 "Codigo do Orgao diverge
// do orgao autorizador".
const TP_AMB = '1'; // 1 = producao, 2 = homologacao

// Defesa contra qualquer erro que por algum motivo acabe incluindo o
// certificado/chave no texto (licao aprendida hoje com o n8n - nunca
// repassar mensagem de erro crua sem checar antes de logar/responder).
function sanitizarErro(texto) {
  const s = String(texto || '');
  if (/-----BEGIN [A-Z ]+-----/.test(s)) {
    return 'Erro de conexao com a Sefaz (detalhe omitido por seguranca).';
  }
  return s.slice(0, 500);
}

let supabaseAdmin = null;
function getSupabaseAdmin() {
  if (!supabaseAdmin) {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      throw new Error('SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY nao configurados neste servico.');
    }
    supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  }
  return supabaseAdmin;
}

async function obterSegredo(nome) {
  const { data, error } = await getSupabaseAdmin().rpc('obter_segredo', { nome });
  if (error || !data) {
    throw new Error(`Segredo "${nome}" nao configurado no Vault.`);
  }
  return data;
}

function montarSoap(chave) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>${TP_AMB}</tpAmb>
          <cUFAutor>${C_UF_AUTOR}</cUFAutor>
          <CNPJ>${CNPJ}</CNPJ>
          <consChNFe>
            <chNFe>${chave}</chNFe>
          </consChNFe>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

function extrairTag(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i'));
  return m ? m[1] : null;
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
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout conectando na Sefaz.'));
    });
    req.on('error', reject);
    req.write(soapBody);
    req.end();
  });
}

/** Uma tentativa de consChNFe — devolve o docZip decodificado se achou,
 * ou {cStat, xMotivo} se não. Não decide o que fazer com "não
 * encontrado" — quem chama (buscarNfePorChave) decide se tenta
 * manifestar e repetir. */
async function consultarUmaVez(chaveLimpa, cert, key) {
  const resposta = await postSoap(cert, key, montarSoap(chaveLimpa));
  if (resposta.statusCode < 200 || resposta.statusCode >= 300) {
    throw new Error(`Sefaz retornou HTTP ${resposta.statusCode} na consulta.`);
  }

  const cStat = extrairTag(resposta.corpo, 'cStat');
  const xMotivo = extrairTag(resposta.corpo, 'xMotivo');
  const docZipMatch = resposta.corpo.match(/<docZip[^>]*schema="([^"]*)"[^>]*>([^<]*)<\/docZip>/i);

  if (!docZipMatch) return { encontrado: false, cStat, xMotivo };

  const xml = zlib.gunzipSync(Buffer.from(docZipMatch[2], 'base64')).toString('utf-8');
  return { encontrado: true, xml };
}

async function buscarNfePorChave(chave) {
  const chaveLimpa = String(chave || '').replace(/\D/g, '');
  if (chaveLimpa.length !== 44) {
    return { status: 400, body: { ok: false, erro: 'chave_invalida', mensagem: 'Chave de acesso precisa ter 44 digitos.' } };
  }

  const [cert, key] = await Promise.all([
    obterSegredo('nfe_certificado_cert_pem'),
    obterSegredo('nfe_certificado_key_pem'),
  ]);

  let resultado = await consultarUmaVez(chaveLimpa, cert, key);

  // cStat 137 "Nenhum documento localizado" quase sempre significa que o
  // destinatário nunca manifestou ciência dessa nota — a Sefaz só libera
  // o documento completo por consChNFe depois disso (confirmado pela NT
  // 2014.002 oficial e testado empiricamente 15/09). Manifesta
  // automaticamente e tenta de novo, uma vez só — não entra em loop se
  // continuar não encontrado por outro motivo (nota realmente não
  // existe, chave errada, etc).
  if (!resultado.encontrado && resultado.cStat === '137') {
    const manifestacao = await manifestarCienciaDaOperacao({
      chave: chaveLimpa,
      cnpj: CNPJ,
      cOrgao: '91', // Ambiente Nacional — ver comentário em C_UF_AUTOR
      tpAmb: TP_AMB,
      cert,
      key,
    });

    if (manifestacao.ok) {
      resultado = await consultarUmaVez(chaveLimpa, cert, key);
    } else {
      return {
        status: 502,
        body: {
          ok: false,
          erro: 'falha_manifestacao',
          mensagem: manifestacao.xMotivo || 'Não foi possível registrar a ciência da operação pra essa nota.',
          cStat: manifestacao.cStat,
        },
      };
    }
  }

  if (!resultado.encontrado) {
    const erro = resultado.cStat === '137' ? 'nao_encontrada' : 'falha_busca';
    const status = resultado.cStat === '137' ? 404 : 502;
    return {
      status,
      body: {
        ok: false,
        erro,
        mensagem: resultado.xMotivo || 'NF-e nao encontrada na Sefaz pra essa chave de acesso, ou nenhum documento retornado.',
        cStat: resultado.cStat,
      },
    };
  }

  return { status: 200, body: { ok: true, xml: resultado.xml } };
}

const server = http.createServer((req, res) => {
  function responderJson(status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  if (req.method === 'GET' && req.url === '/health') {
    responderJson(200, { ok: true });
    return;
  }

  if (req.method !== 'POST' || req.url !== '/buscar-nfe-por-chave') {
    responderJson(404, { ok: false, erro: 'rota_invalida' });
    return;
  }

  if (SERVICE_TOKEN && req.headers['x-service-token'] !== SERVICE_TOKEN) {
    responderJson(401, { ok: false, erro: 'nao_autorizado' });
    return;
  }

  let corpo = '';
  req.on('data', (chunk) => {
    corpo += chunk;
    // trava tamanho absurdo de corpo (defesa simples contra abuso)
    if (corpo.length > 10_000) req.destroy();
  });
  req.on('end', async () => {
    let payload;
    try {
      payload = JSON.parse(corpo || '{}');
    } catch {
      responderJson(400, { ok: false, erro: 'json_invalido' });
      return;
    }

    try {
      const resultado = await buscarNfePorChave(payload.chave);
      responderJson(resultado.status, resultado.body);
    } catch (e) {
      responderJson(500, { ok: false, erro: 'erro_interno', mensagem: sanitizarErro(e && e.message) });
    }
  });
});

server.listen(PORT, () => {
  console.log(`nfe-sefaz-service ouvindo na porta ${PORT}`);
});
