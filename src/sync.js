// Sincronizacao continua com a Sefaz via distNSU (NFeDistribuicaoDFe), que
// mantem um cache local das NF-e completas em `nfe_cache_distribuicao`.
//
// Por que isso existe, achado real 15/09: consChNFe (busca pontual por
// chave, que era o unico metodo usado antes) tem um indice proprio na Sefaz
// que fica dessincronizado do indice de distNSU - uma NF-e ja autorizada E
// ja manifestada (cStat 135 confirmado, protocolo real) continuava
// retornando cStat 137 "nenhum documento localizado" via consChNFe, sem
// nenhum atraso documentado que justificasse isso (NT 2014.002 secao 3.7).
// A mesma chave, no mesmo instante, apareceu imediatamente via distNSU
// (cStat 138, docZip com o procNFe completo). Confirmado com teste direto
// contra a Sefaz, nao suposicao.
//
// Arquitetura: poll continuo em distNSU mantendo um cursor de NSU
// persistido (nunca reconsultar com ultNSU=0 de novo - isso rendeu um
// cStat 656 "Consumo Indevido" num teste). Toda vez que aparece um resNFe
// (resumo, antes da manifestacao) manifesta Ciencia da Operacao na hora.
// Toda vez que aparece um procNFe (documento completo, ja liberado), cacheia
// na tabela. A busca por chave (index.js) consulta o cache primeiro -
// instantanea - e so cai pra sincronizacao sob demanda se nao achar.

const zlib = require('zlib');
const { manifestarCienciaDaOperacao } = require('./manifestacao');

const SEFAZ_HOSTNAME = 'www1.nfe.fazenda.gov.br';
const SEFAZ_PATH = '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx';
const SOAP_ACTION = 'http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse';

// Sefaz pede um intervalo minimo de 1h depois de um cStat 137 (nenhum
// documento a mais) antes de reconsultar distNSU - NT 2014.002 secao 3.5.
const COOLDOWN_SEM_NOVIDADE_MS = 60 * 60 * 1000;

// Trava simples pra nunca ter duas sincronizacoes rodando ao mesmo tempo
// (poll de fundo + sincronizacao sob demanda disparada por uma busca).
let sincronizando = false;

function montarSoapDistNsu({ tpAmb, cUFAutor, cnpj, ultNSU }) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>${tpAmb}</tpAmb>
          <cUFAutor>${cUFAutor}</cUFAutor>
          <CNPJ>${cnpj}</CNPJ>
          <distNSU>
            <ultNSU>${ultNSU}</ultNSU>
          </distNSU>
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

function postSoap({ https, cert, key, soapBody }) {
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
      reject(new Error('Timeout conectando na Sefaz (distNSU).'));
    });
    req.on('error', reject);
    req.write(soapBody);
    req.end();
  });
}

async function obterEstado(supabase, cnpj) {
  const { data, error } = await supabase
    .from('nfe_sync_estado')
    .select('ultimo_nsu, ultima_consulta_sem_novidade_em')
    .eq('cnpj', cnpj)
    .maybeSingle();
  if (error) throw new Error(`Falha lendo nfe_sync_estado: ${error.message}`);
  return data || { ultimo_nsu: '000000000000000', ultima_consulta_sem_novidade_em: null };
}

async function salvarEstado(supabase, cnpj, { ultimoNsu, semNovidadeAgora }) {
  const patch = { cnpj, ultimo_nsu: ultimoNsu, atualizado_em: new Date().toISOString() };
  if (semNovidadeAgora) patch.ultima_consulta_sem_novidade_em = new Date().toISOString();
  const { error } = await supabase.from('nfe_sync_estado').upsert(patch, { onConflict: 'cnpj' });
  if (error) throw new Error(`Falha salvando nfe_sync_estado: ${error.message}`);
}

async function cachearNfe(supabase, chave, xml, nsu) {
  const { error } = await supabase
    .from('nfe_cache_distribuicao')
    .upsert({ chave, xml, nsu, recebido_em: new Date().toISOString() }, { onConflict: 'chave' });
  if (error) throw new Error(`Falha salvando nfe_cache_distribuicao: ${error.message}`);
}

/** Processa os documentos de um lote de distNSU: cacheia procNFe completos
 * e manifesta Ciencia da Operacao pros resNFe (resumo) ainda nao vistos. */
async function processarDocumentos(supabase, docs, { cnpj, cert, key }) {
  for (const doc of docs) {
    let xml;
    try {
      xml = zlib.gunzipSync(Buffer.from(doc.conteudo, 'base64')).toString('utf-8');
    } catch (e) {
      continue; // docZip corrompido/inesperado - pula, nao trava o lote inteiro
    }

    if (doc.schema.startsWith('procNFe')) {
      const m = xml.match(/Id="NFe(\d{44})"/);
      if (m) await cachearNfe(supabase, m[1], xml, doc.nsu);
      continue;
    }

    if (doc.schema.startsWith('resNFe')) {
      const chave = extrairTag(xml, 'chNFe');
      if (chave) {
        // Best-effort: se ja manifestada antes (reprocessamento, etc) a
        // Sefaz so vai rejeitar o evento duplicado - nao interrompe o lote.
        try {
          await manifestarCienciaDaOperacao({ chave, cnpj, cOrgao: '91', tpAmb: '1', cert, key });
        } catch (e) {
          // Erro de rede/manifestacao pra uma chave nao deve travar o resto
          // do lote - a proxima rodada do poll tenta de novo.
        }
      }
      continue;
    }
    // resEvento e outros schemas: so precisam ser consumidos pra avancar o
    // NSU, nada pra cachear.
  }
}

/** Um ciclo de sincronizacao: consome lotes de distNSU a partir do cursor
 * salvo ate a Sefaz dizer "nenhum documento a mais" (cStat 137) ou até
 * `maxLotes` lotes (protecao contra loop infinito). Respeita o cooldown de
 * 1h da Sefaz depois de um 137 anterior - nesse caso nao faz nada. */
async function sincronizar({ https, supabase, cnpj, cUFAutor, tpAmb, cert, key, maxLotes = 5 }) {
  if (sincronizando) return { pulou: true, motivo: 'sincronizacao_em_andamento' };
  sincronizando = true;
  try {
    const estado = await obterEstado(supabase, cnpj);

    if (estado.ultima_consulta_sem_novidade_em) {
      const desde = Date.now() - new Date(estado.ultima_consulta_sem_novidade_em).getTime();
      if (desde < COOLDOWN_SEM_NOVIDADE_MS) {
        return { pulou: true, motivo: 'cooldown_sefaz', restamMs: COOLDOWN_SEM_NOVIDADE_MS - desde };
      }
    }

    let ultNSU = estado.ultimo_nsu;
    let lotes = 0;
    let documentosProcessados = 0;

    while (lotes < maxLotes) {
      lotes += 1;
      const soapBody = montarSoapDistNsu({ tpAmb, cUFAutor, cnpj, ultNSU });
      const resposta = await postSoap({ https, cert, key, soapBody });
      if (resposta.statusCode < 200 || resposta.statusCode >= 300) {
        throw new Error(`Sefaz retornou HTTP ${resposta.statusCode} no distNSU.`);
      }

      const cStat = extrairTag(resposta.corpo, 'cStat');
      const novoUltNSU = extrairTag(resposta.corpo, 'ultNSU');

      if (cStat === '656') {
        // Consumo indevido - nao deveria acontecer se o cooldown acima
        // estiver certo, mas se acontecer (relogio dessincronizado etc),
        // registra o cooldown mesmo assim pra nao insistir.
        await salvarEstado(supabase, cnpj, { ultimoNsu: ultNSU, semNovidadeAgora: true });
        return { pulou: true, motivo: 'consumo_indevido_656' };
      }

      if (cStat === '137') {
        if (novoUltNSU) ultNSU = novoUltNSU;
        await salvarEstado(supabase, cnpj, { ultimoNsu: ultNSU, semNovidadeAgora: true });
        return { ok: true, documentosProcessados, motivo: 'sem_mais_documentos' };
      }

      if (cStat !== '138') {
        const xMotivo = extrairTag(resposta.corpo, 'xMotivo');
        throw new Error(`distNSU retornou cStat ${cStat}: ${xMotivo || '(sem motivo)'}`);
      }

      const docs = [...resposta.corpo.matchAll(/<docZip NSU="([^"]*)" schema="([^"]*)">([^<]*)<\/docZip>/g)].map(
        ([, nsu, schema, conteudo]) => ({ nsu, schema, conteudo }),
      );
      await processarDocumentos(supabase, docs, { cnpj, cert, key });
      documentosProcessados += docs.length;

      ultNSU = novoUltNSU || ultNSU;
      const maxNSU = extrairTag(resposta.corpo, 'maxNSU');
      // Persiste o progresso a cada lote - se cair no meio, a proxima
      // rodada continua do ponto certo em vez de reconsultar do zero.
      await salvarEstado(supabase, cnpj, { ultimoNsu: ultNSU, semNovidadeAgora: false });

      if (!maxNSU || ultNSU >= maxNSU) {
        return { ok: true, documentosProcessados, motivo: 'lote_final_alcancado' };
      }
    }

    return { ok: true, documentosProcessados, motivo: 'limite_de_lotes_atingido' };
  } finally {
    sincronizando = false;
  }
}

async function buscarNoCache(supabase, chave) {
  const { data, error } = await supabase
    .from('nfe_cache_distribuicao')
    .select('xml')
    .eq('chave', chave)
    .maybeSingle();
  if (error) throw new Error(`Falha lendo nfe_cache_distribuicao: ${error.message}`);
  return data ? data.xml : null;
}

module.exports = { sincronizar, buscarNoCache };
