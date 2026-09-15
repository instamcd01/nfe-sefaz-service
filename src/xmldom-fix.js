// xmldom 0.9.x passou a exigir `mimeType` explícito em `parseFromString`
// (antes era opcional, defaultava sozinho) — `xml-crypto` ainda não foi
// atualizado pra passar isso, e sem esse patch toda assinatura falha com
// TypeError. Atualizamos o xmldom mesmo assim (não a versão antiga que o
// xml-crypto pede) porque a antiga tem vulnerabilidades reais conhecidas
// (injeção de XML, bypass de limite de expansão de entidade — ver
// package.json/overrides). Só injeta o default que o próprio xmldom
// documenta como esperado ('application/xml') quando a chamada não passa
// nada — precisa ser importado ANTES de `xml-crypto` em qualquer arquivo
// que for assinar XML.
const { DOMParser } = require('@xmldom/xmldom');

const original = DOMParser.prototype.parseFromString;
DOMParser.prototype.parseFromString = function (source, mimeType) {
  return original.call(this, source, mimeType || 'application/xml');
};
