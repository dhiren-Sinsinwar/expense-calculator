// Find My Expense — generic transaction-alert parser.
// Works on any bank/card/UPI alert that uses standard wording, not per-bank templates.
(function (root) {
  const CUR = [
    ['INR', /(?:₹|\bINR\b|\bRs\.?(?=\s?\d)|\bRs\b)/i],
    ['USD', /(?:\bUSD\b|US\$|\$(?=\s?\d))/i],
    ['EUR', /(?:\bEUR\b|€)/i],
    ['GBP', /(?:\bGBP\b|£)/i],
    ['AED', /\bAED\b/i],
    ['SGD', /\bSGD\b/i],
    ['THB', /\bTHB\b/i],
    ['JPY', /(?:\bJPY\b|¥)/i],
  ];
  const AMOUNT_RE = /(₹|\bINR\b|\bRs\.?|\bUSD\b|US\$|\$|\bEUR\b|€|\bGBP\b|£|\bAED\b|\bSGD\b|\bTHB\b|\bJPY\b|¥)\s?:?\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)/gi;

  // Things that are NOT a spend even though they mention money
  const NOT_TXN = /\b(otp|one[\s-]time password|statement (?:is )?(?:generated|ready)|minimum (?:amount )?due|total (?:amount )?due|bill (?:is )?(?:generated|due)|payment due|due date|pre[\s-]?approved|offer|eligible|reward points? (?:earned|balance)|emi conversion|credit limit (?:increase|enhance)|kyc|login|password|failed|declined|unsuccessful|could not be processed|request(?:ed)? money|collect request|mandate (?:created|registered)|autopay (?:set ?up|registered))\b/i;
  // Paying your own card bill or moving money between own accounts — would double count
  const TRANSFER = /\b(payment (?:of .{0,30})?(?:has been )?received (?:towards|on|for) your .{0,30}card|thank you for (?:your )?payment|card (?:bill|dues) payment|self[\s-]transfer|to your own account)\b/i;
  const REFUND = /\b(refund(?:ed)?|revers(?:ed|al)|cash ?back|chargeback|credit(?:ed)? back)\b/i;
  const DEBIT = /\b(debited|spent|charged|paid|purchase|used (?:for|at)|has been used|withdrawn|withdrawal|sent|txn of|transaction of|charge of|a charge|transaction amount|txn amount|amount debited|payment of|deducted|auto[\s-]?debit|transferred)\b/i;

  const BALANCE_TAIL = /(?:avl\.?\s*bal(?:ance)?|available\s+(?:bal(?:ance)?|credit\s+limit|limit)|avl\.?\s*l(?:i)?m(?:i)?t|a\/c\s+bal|account\s+balance|total\s+outstanding|outstanding|bal(?:ance)?\s*(?:is|:))[^.\n]*/gi;

  const BANKS = [
    ['HDFC Bank', /hdfc/i], ['ICICI Bank', /icici/i], ['SBI', /\bsbi\b|sbicard|onlinesbi|statebank/i],
    ['Axis Bank', /axis/i], ['Kotak', /kotak/i], ['Yes Bank', /yes ?bank|yesbank/i], ['IDFC First', /idfc/i],
    ['IndusInd', /indus ?ind/i], ['AU Bank', /\bau ?(small finance )?bank|aubank/i], ['RBL Bank', /\brbl/i],
    ['Standard Chartered', /standard chartered|\bsc\.com/i], ['HSBC', /hsbc/i], ['Amex', /amex|american ?express|aexp/i],
    ['Citi', /\bciti/i], ['Federal Bank', /federal ?bank|federalbank/i], ['Bank of Baroda', /bank ?of ?baroda|bankofbaroda|\bbob\b/i],
    ['PNB', /\bpnb\b|punjab national/i], ['Canara Bank', /canara/i], ['Union Bank', /union ?bank/i], ['IDBI', /idbi/i],
    ['OneCard', /onecard|getonecard/i], ['Slice', /\bslice/i], ['Jupiter', /jupiter/i], ['Fi', /\bfi\.money|epifi/i],
    ['Paytm', /paytm/i], ['PhonePe', /phonepe/i], ['Google Pay', /google ?pay|gpay/i], ['Amazon Pay', /amazon ?pay/i],
    ['CRED', /\bcred\b|cred\.club/i], ['Mobikwik', /mobikwik/i], ['Bank of India', /bank ?of ?india|bankofindia/i],
  ];

  const CATEGORY_RULES = [
    ['Food & Dining', /swiggy|zomato|eatsure|domino|pizza|mcdonald|kfc|burger|starbucks|cafe|coffee|restaurant|dine|chaayos|third wave|blue tokai|haldiram|subway|eatclub|box8|faasos/i],
    ['Groceries', /bigbasket|blinkit|zepto|instamart|dmart|jiomart|grofers|more retail|reliance fresh|nature'?s basket|spencer|ratnadeep|milkbasket|country delight|licious|fresh/i],
    ['Transport', /uber|\bola\b|olacabs|rapido|namma yatri|metro|fastag|petrol|fuel|\bhpcl\b|\bbpcl\b|\biocl?\b|indian oil|shell|parking|blusmart|redbus|yulu/i],
    ['Travel', /makemytrip|goibibo|cleartrip|yatra|ixigo|easemytrip|indigo|air ?india|vistara|akasa|spicejet|irctc|booking\.com|agoda|airbnb|oyo|marriott|taj|hyatt|hilton|expedia|emirates|singapore air|thomas cook|visa fee|airport/i],
    ['Shopping', /amazon(?! ?pay)|flipkart|myntra|ajio|nykaa|meesho|tata ?cliq|croma|reliance digital|decathlon|ikea|lifestyle|westside|zara|h&m|uniqlo|apple store|vijay sales|firstcry|pepperfry|urban ladder/i],
    ['Bills & Utilities', /airtel|\bjio\b|vodafone|\bvi\b|bsnl|bescom|electricity|power|water|gas|broadband|act fibernet|hathway|tata ?play|dth|recharge|insurance|lic\b|rent|maintenance|society|nobroker|bbmp|tax/i],
    ['Subscriptions', /netflix|spotify|youtube|prime video|hotstar|disney|sonyliv|zee5|jiocinema|apple\.com|icloud|google ?(?:one|play|cloud|storage)|microsoft|office 365|adobe|notion|canva|claude|anthropic|openai|chatgpt|github|linkedin|medium|substack|dropbox|zoom|slack|figma/i],
    ['Entertainment', /bookmyshow|\bpvr\b|inox|cinepolis|district|paytm insider|steam|playstation|xbox|gaming|concert|event/i],
    ['Health', /apollo|pharmeasy|1mg|netmeds|medplus|hospital|clinic|pharmacy|chemist|diagnostic|lab|practo|cult\.?fit|cultfit|healthify|gym|dental|medic/i],
  ];

  function decodeEntities(s) {
    return s.replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&#8377;|&#x20b9;/gi, '₹')
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
  }
  function htmlToText(html) {
    return decodeEntities(html
      .replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|tr|li|h\d)>/gi, '\n').replace(/<[^>]+>/g, ' '));
  }
  function clean(s) { return s.replace(/[ \t\u00a0]+/g, ' ').replace(/\n\s*/g, '\n').trim(); }
  function num(s) { return parseFloat(s.replace(/,/g, '')); }

  function currencyOf(sym) {
    for (const [code, re] of CUR) if (re.test(sym)) return code;
    return 'INR';
  }

  function detectBank(from, text) {
    for (const [name, re] of BANKS) if (re.test(from)) return name;
    for (const [name, re] of BANKS) if (re.test(text.slice(0, 400))) return name;
    const m = from.match(/^\s*"?([^"<@]+?)"?\s*</);
    return m ? m[1].trim() : '';
  }

  function detectInstrument(text) {
    const upi = /\bUPI\b/i.test(text);
    const card = text.match(/(credit|debit)?\s*card\s*(?:no\.?|number)?\s*(?:ending|ending with|ending in|end(?:ing)? no\.?)?\s*(?:[xX*•]+\s*)?[-:]?\s*[xX*•]*\s*(\d{4})\b/i)
      || text.match(/\bcard\s+[xX*•]{2,}\s*(\d{4})\b/i);
    if (card) {
      const last4 = card[2] || card[1];
      const kind = card[2] && card[1] ? (card[1][0].toUpperCase() + card[1].slice(1).toLowerCase() + ' card') : 'Card';
      return { kind, last4 };
    }
    const acct = text.match(/\b(?:a\/c|acct|account|ac)\s*(?:no\.?|number)?\s*[:\-]?\s*[xX*•]*\s*(\d{3,6})\b/i);
    if (acct) return { kind: upi ? 'UPI' : 'Account', last4: acct[1].slice(-4) };
    if (upi) return { kind: 'UPI', last4: '' };
    return { kind: '', last4: '' };
  }

  function tidyMerchant(m) {
    if (!m) return '';
    m = m.replace(/\s+/g, ' ').replace(/^(?:the|m\/s\.?|ms\.?)\s+/i, '')
      .replace(/\s+(?:on|via|using|ref|reference|txn|transaction|upi|imps|neft|dated|at|for|from|with|by|is|has|have|was|were|thru|through)\b.*$/i, '')
      .replace(/[.,;:\-*_\s]+$/, '').replace(/^[.,;:\-*_\s]+/, '').trim();
    if (m.length < 2 || /^\d+$/.test(m) || /^(your|a|an|the|account|card|bank)$/i.test(m)) return '';
    return m.length > 40 ? m.slice(0, 40).trim() : m;
  }

  const NARR_CODES = /^(mob|tpft|tpar|upi|imps|neft|rtgs|p2a|p2m|ib|inb|ach|nach|ecs|pos|ecom|dr|cr|ft|bil|onl|mmt|net|trf|ref|ifsc)$/i;
  function fromNarration(text) {
    const m = text.match(/\b(?:by|info:?|to|towards)\s*:?\s*([A-Za-z][A-Za-z0-9.@_-]*\/(?:[A-Za-z0-9.@ _-]*\/)+[A-Za-z0-9.@ _\/-]*)/i);
    if (!m) return '';
    const parts = m[1].split('/').map(x => x.replace(/\.$/, '').trim())
      .filter(x => x && !NARR_CODES.test(x) && /[A-Za-z]{2,}/.test(x) && !/^\d+$/.test(x));
    parts.sort((a, b) => (/\s/.test(b) - /\s/.test(a)) || b.length - a.length);
    return parts[0] || '';
  }

  function detectMerchant(text) {
    const n = fromNarration(text);
    if (n) { const t = tidyMerchant(n); if (t) return t; }
    const pats = [
      /\bat\s+([A-Za-z0-9][A-Za-z0-9 &*.'\-_/@]{1,60}?)(?=\s+(?:on|via|using|ref|dated|has|have|was|is|for)\b|\.\s|\.?$|,|\n)/i,
      /\b(?:Info|Merchant(?: Name)?|Payee(?: Name)?|Paid to|Beneficiary)\s*[:\-]\s*([^\n.,;]{2,60})/i,
      /\bto\s+(?:VPA\s+)?([A-Za-z0-9][A-Za-z0-9 &.'\-_]*@[A-Za-z0-9.\-]+)/i,
      /\b(?:trf|transfer(?:red)?|sent|paid)\s+to\s+([A-Za-z0-9][A-Za-z0-9 &*.'\-_]{1,60}?)(?=\s+(?:on|via|ref|has|have|was|is)\b|\.\s|\.?$|,|\n)/i,
      /\btowards\s+([A-Za-z0-9][A-Za-z0-9 &*.'\-_]{1,60}?)(?=\s+(?:on|via|has|was|is)\b|\.\s|\.?$|,|\n)/i,
      /\bto\s+([A-Z][A-Za-z0-9 &*.'\-_]{1,60}?)(?=\s+(?:on|via|ref|has|have|was|is)\b|\.\s|\.?$|,|\n)/,
      /\bfrom\s+([A-Za-z0-9][A-Za-z0-9 &*.'\-_]{1,60}?)(?=\s+(?:on|for|ref|has|have|was|is)\b|\.\s|\.?$|,|\n)/i,
    ];
    for (const re of pats) {
      const m = text.match(re);
      if (m) { const t = tidyMerchant(m[1]); if (t) return t; }
    }
    return '';
  }

  const CAT_RE = CATEGORY_RULES.map(([c, re]) => [c, new RegExp('(?:^|[^a-z])(?:' + re.source + ')', 'i')]);
  function guessCategory(merchant, subject) {
    for (const [cat, re] of CAT_RE) if (re.test(merchant || '')) return cat;
    for (const [cat, re] of CAT_RE) if (re.test(subject || '')) return cat;
    if (/\b(emi|loan|nach|ecs|ach)\b/i.test((merchant || '') + ' ' + (subject || ''))) return 'Loans & EMI';
    return 'Other';
  }

  // Main entry. msg = { id, subject, from, text, html, date (ms) }
  // Returns { status: 'txn'|'skip'|'unparsed', reason?, txn? }
  function parseTransaction(msg) {
    const bodyText = msg.text && msg.text.trim().length > 30 ? msg.text : htmlToText(msg.html || msg.text || '');
    const text = clean(decodeEntities((msg.subject || '') + '\n' + bodyText));
    const head = text.slice(0, 1500);

    if (TRANSFER.test(head)) return { status: 'skip', reason: 'card bill payment / own transfer' };
    const isRefund = REFUND.test(head);
    const isDebit = DEBIT.test(head);
    if (!isRefund && !isDebit) {
      if (/\bcredited\b/i.test(head)) return { status: 'skip', reason: 'money received (not a spend)' };
      return { status: 'unparsed', reason: 'no spend wording found' };
    }
    if (NOT_TXN.test(head) && !/\b(debited|spent|charged)\b/i.test(head.slice(0, 300)))
      return { status: 'skip', reason: 'not a transaction (OTP, statement, offer, failed…)' };
    if (!isRefund && /\bcredited\b/i.test(head) && !/\bdebited\b/i.test(head))
      return { status: 'skip', reason: 'money received (not a spend)' };

    // Strip balance/limit phrases so we don't pick those amounts
    const scan = head.replace(BALANCE_TAIL, ' ');
    // Prefer the amount nearest a spend/refund keyword
    const kw = isRefund ? REFUND : DEBIT;
    const amounts = [];
    let m; AMOUNT_RE.lastIndex = 0;
    while ((m = AMOUNT_RE.exec(scan))) {
      const v = num(m[2]);
      if (v > 0 && v < 1e8) amounts.push({ v, cur: currencyOf(m[1]), at: m.index });
    }
    if (!amounts.length) return { status: 'unparsed', reason: 'no amount found' };
    const kwPos = scan.search(kw);
    amounts.sort((a, b) => Math.abs(a.at - kwPos) - Math.abs(b.at - kwPos));
    const amt = amounts[0];

    const merchant = detectMerchant(scan);
    const inst = detectInstrument(head);
    const bank = detectBank(msg.from || '', text);
    const payment = [bank, inst.kind, inst.last4 ? '••' + inst.last4 : ''].filter(Boolean).join(' ');

    return {
      status: 'txn',
      txn: {
        msgId: msg.id,
        date: new Date(msg.date || Date.now()).toISOString().slice(0, 10),
        amount: isRefund ? -amt.v : amt.v,
        currency: amt.cur,
        merchant: merchant || (isRefund ? 'Refund' : 'Unknown merchant'),
        category: guessCategory(merchant, (msg.subject || '') + ' ' + (/\b(nach|ecs|emi|loan)\b/i.test(head) ? 'nach' : '')),
        payment,
        type: isRefund ? 'refund' : 'debit',
        subject: msg.subject || '',
      }
    };
  }

  // Gmail search used to pre-filter the inbox
  function buildQuery(days) {
    return `newer_than:${days}d -category:promotions -category:social -in:chats ` +
      `(debited OR spent OR charged OR "has been used" OR "transaction alert" OR "txn" OR "payment of" OR "paid to" OR "sent to" OR refund OR reversed OR reversal OR withdrawn OR "auto debit" OR "autopay") ` +
      `(Rs OR "Rs." OR INR OR ₹ OR USD OR AED OR EUR OR GBP)`;
  }

  const api = { parseTransaction, buildQuery, htmlToText, guessCategory };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.FMEParser = api;
})(typeof window !== 'undefined' ? window : globalThis);
