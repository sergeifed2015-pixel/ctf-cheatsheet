/* ============================================================
   CTF File Analyzer — client-side analysis engine
   ============================================================ */
const Analyzer = (function () {

const MAGIC = [
  { bytes:[0x7f,0x45,0x4c,0x46],           type:"ELF",    label:"ELF исполняемый (Linux/UNIX)" },
  { bytes:[0x4d,0x5a],                      type:"PE",     label:"PE исполняемый (Windows)" },
  { bytes:[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a], type:"PNG", label:"Изображение PNG" },
  { bytes:[0xff,0xd8,0xff],                 type:"JPEG",   label:"Изображение JPEG" },
  { bytes:[0x47,0x49,0x46,0x38],            type:"GIF",    label:"Изображение GIF" },
  { bytes:[0x42,0x4d],                      type:"BMP",    label:"Изображение BMP" },
  { bytes:[0x50,0x4b,0x03,0x04],            type:"ZIP",    label:"ZIP-архив" },
  { bytes:[0x52,0x61,0x72,0x21],            type:"RAR",    label:"RAR-архив" },
  { bytes:[0x25,0x50,0x44,0x46],            type:"PDF",    label:"PDF-документ" },
  { bytes:[0x1f,0x8b],                      type:"GZIP",   label:"GZIP-архив" },
  { bytes:[0xfd,0x37,0x7a,0x58,0x5a,0x00], type:"XZ",     label:"XZ-архив" },
  { bytes:[0x42,0x5a,0x68],                 type:"BZ2",    label:"BZip2-архив" },
  { bytes:[0xca,0xfe,0xba,0xbe],            type:"JAVA",   label:"Java .class файл" },
  { bytes:[0xcf,0xfa,0xed,0xfe],            type:"MACHO64",label:"macOS Mach-O 64-bit" },
  { bytes:[0xce,0xfa,0xed,0xfe],            type:"MACHO32",label:"macOS Mach-O 32-bit" },
  { bytes:[0x53,0x51,0x4c,0x69],            type:"SQLITE", label:"SQLite база данных" },
  { bytes:[0xd0,0xcf,0x11,0xe0],            type:"OLE",    label:"MS Office / OLE документ" },
  { bytes:[0x4f,0x67,0x67,0x53],            type:"OGG",    label:"OGG аудио/видео" },
  { bytes:[0x49,0x44,0x33],                 type:"MP3",    label:"MP3 аудио" },
  { bytes:[0x52,0x49,0x46,0x46],            type:"RIFF",   label:"RIFF (WAV/AVI)" },
  { bytes:[0x37,0x7a,0xbc,0xaf,0x27,0x1c], type:"7ZIP",   label:"7-Zip архив" },
  { bytes:[0x1a,0x45,0xdf,0xa3],            type:"WEBM",   label:"WebM/MKV видео" },
];

/* ---- helpers ---- */
function detectType(b) {
  for (const m of MAGIC) if (b.length >= m.bytes.length && m.bytes.every((v,i) => b[i]===v)) return {...m};
  let p=0, n=Math.min(b.length,512);
  for (let i=0;i<n;i++) if (b[i]>=32&&b[i]<=126) p++;
  if (p/n > 0.8) return {type:"TEXT", label:"Текстовый файл"};
  return {type:"BINARY", label:"Бинарный файл (формат не опознан)"};
}

function fmtSize(n) {
  if (n<1024) return n+" Б";
  if (n<1048576) return (n/1024).toFixed(1)+" КБ";
  return (n/1048576).toFixed(1)+" МБ";
}

function entropy(b) {
  const f=new Uint32Array(256);
  for (const v of b) f[v]++;
  let e=0,l=b.length;
  for (const v of f) { if(!v) continue; const p=v/l; e-=p*Math.log2(p); }
  return e;
}

function extractStrings(b, minLen=4) {
  const out=[]; let cur="";
  const lim=Math.min(b.length,2*1024*1024);
  for (let i=0;i<lim;i++) {
    const v=b[i];
    if (v>=32&&v<127) cur+=String.fromCharCode(v);
    else { if(cur.length>=minLen) out.push(cur); cur=""; }
  }
  if (cur.length>=minLen) out.push(cur);
  return out;
}

function toText(b) {
  try { return new TextDecoder("utf-8",{fatal:false}).decode(b.slice(0,1024*1024)); }
  catch { let s=""; for (let i=0;i<Math.min(b.length,65536);i++) s+=String.fromCharCode(b[i]); return s; }
}

function findFlags(text) {
  const s = new Set();
  // prefix: only letters/underscores (real CTF prefixes never contain digits)
  // content: only printable ASCII 0x20-0x7e, must have at least one alphanumeric
  // [^\x00-\x1f\x7f-\xff}] = printable ASCII (0x20-0x7e) excluding closing brace
  const pat = /([A-Za-z_]{2,20})\{([^\x00-\x1f\x7f-\xff}]{3,120})\}/g;
  let m;
  while ((m = pat.exec(text)) !== null) {
    if (/[A-Za-z0-9]/.test(m[2])) s.add(m[0]);
  }
  return [...s];
}

function findEmbedded(b) {
  const found=[];
  const lim=Math.min(b.length,4*1024*1024);
  for (const m of MAGIC) {
    for (let i=4;i<lim-m.bytes.length;i++) {
      if (m.bytes.every((v,j)=>b[i+j]===v)) {
        found.push({type:m.type,label:m.label,offset:i});
        i+=m.bytes.length;
      }
    }
  }
  return found;
}

function hexDump(b, lines=8) {
  let out="";
  const n=Math.min(b.length,lines*16);
  for (let i=0;i<n;i+=16) {
    const row=b.slice(i,i+16);
    const hex=Array.from(row).map(v=>v.toString(16).padStart(2,"0")).join(" ");
    const asc=Array.from(row).map(v=>(v>=32&&v<127)?String.fromCharCode(v):".").join("");
    out+=`${i.toString(16).padStart(8,"0")}  ${hex.padEnd(47)}  |${asc}|\n`;
  }
  return out;
}

function tryBase64(text) {
  const c=text.replace(/[\r\n\s]/g,"");
  if (c.length<8||!/^[A-Za-z0-9+/]+=*$/.test(c)) return null;
  try { return atob(c); } catch { return null; }
}

function tryHex(text) {
  const c=text.replace(/[\r\n\s:]/g,"").replace(/^0x/,"");
  if (c.length<8||c.length%2!==0||!/^[0-9a-fA-F]+$/.test(c)) return null;
  try {
    let s="";
    for (let i=0;i<c.length;i+=2) s+=String.fromCharCode(parseInt(c.slice(i,i+2),16));
    return s;
  } catch { return null; }
}

function rot13(t) {
  return t.replace(/[A-Za-z]/g,c=>{ const b=c<='Z'?65:97; return String.fromCharCode((c.charCodeAt(0)-b+13)%26+b); });
}

function analyzeELF(b) {
  if (b.length<20) return null;
  const bits=b[4]===2?64:32;
  const endian=b[5]===1?"Little-Endian":"Big-Endian";
  const etype=b[16]|(b[17]<<8);
  const emachine=b[18]|(b[19]<<8);
  const machines={0x03:"x86 (i386)",0x28:"ARM",0x3e:"x86-64 (AMD64)",0xb7:"AArch64 (ARM64)",0xf3:"RISC-V"};
  const etypes={1:"REL (объектный)",2:"EXEC (исполняемый, no PIE)",3:"DYN (shared/PIE)",4:"CORE"};
  return {bits, endian, arch:machines[emachine]||`0x${emachine.toString(16)}`, etype:etypes[etype]||`0x${etype.toString(16)}`, isPIE:etype===3};
}

function analyzePNG(b) {
  if (b.length<26) return null;
  const w=(b[16]<<24)|(b[17]<<16)|(b[18]<<8)|b[19];
  const h=(b[20]<<24)|(b[21]<<16)|(b[22]<<8)|b[23];
  const colors={0:"Grayscale",2:"RGB",3:"Indexed",4:"Grayscale+Alpha",6:"RGBA"};
  return {w,h,depth:b[24],color:colors[b[25]]||"?"};
}

function analyzeJPEG(b) {
  for (let i=2;i<b.length-8;i++) {
    if (b[i]===0xff&&(b[i+1]&0xf0)===0xc0&&b[i+1]!==0xc4&&b[i+1]!==0xc8&&b[i+1]!==0xcc) {
      return {w:(b[i+7]<<8)|b[i+8], h:(b[i+5]<<8)|b[i+6]};
    }
  }
  return null;
}

function jpegTail(b) {
  for (let i=b.length-2;i>=0;i--) if (b[i]===0xff&&b[i+1]===0xd9) return i+2<b.length?b.slice(i+2):null;
  return null;
}

function pngTail(b) {
  const IEND=[0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82];
  for (let i=b.length-8;i>=0;i--) if (IEND.every((v,j)=>b[i+j]===v)) return i+8<b.length?b.slice(i+8):null;
  return null;
}

/* ---- category analyzers ---- */
function analyzeReverse(ctx) {
  const {fileName,bytes:b,type,entropy:ent}=ctx;
  const results=[];
  const elf=type.type==="ELF"?analyzeELF(b):null;

  let fileOut=`${fileName}: ${type.label}`;
  const fileFindings=[];
  if (elf) {
    fileOut=`${fileName}: ELF ${elf.bits}-bit ${elf.endian}\n  Архитектура: ${elf.arch}\n  Тип: ${elf.etype}`;
    if (elf.isPIE) fileFindings.push({token:"PIE/DYN",desc:"ASLR включён — базовый адрес случайный. Для ROP/ret2libc нужна утечка адреса."});
    else fileFindings.push({token:"No PIE",desc:"Фиксированные адреса (0x400000+) — удобно для ROP и GOT overwrite атак."});
  } else if (type.type==="PE") {
    fileFindings.push({token:"MZ/PE",desc:"Windows PE-файл. Открывайте в x64dbg (динамика) или Ghidra/IDA (статика)."});
  }
  results.push({tool:"file",cmd:`file ${fileName}`,output:fileOut,findings:fileFindings});

  const strs=extractStrings(b,6);
  const flags=findFlags(strs.join("\n"));
  const interesting=strs.filter(s=>/flag|ctf|pass|secret|key|win|admin|token/i.test(s)).slice(0,12);
  const strFindings=[
    ...flags.map(f=>({token:f,desc:"Возможный флаг CTF — проверьте!",isFlag:true})),
    ...interesting.filter(s=>!flags.includes(s)).map(s=>({token:s.slice(0,40),desc:"Интересная строка — может быть подсказкой."})),
  ];
  const strOut=strs.slice(0,40).join("\n")+(strs.length>40?`\n... (ещё ${strs.length-40})` : "");
  results.push({tool:"strings",cmd:`strings -n 6 ${fileName}`,output:strOut||"(строки не найдены)",findings:strFindings,highlight:flags.length>0});

  results.push({tool:"xxd",cmd:`xxd ${fileName} | head -16`,output:hexDump(b,8),findings:[{token:type.label,desc:"Magic bytes — первые байты определяют формат файла независимо от расширения."}]});

  const entLabel=ent>7.5?"очень высокая — зашифрован/запакован":ent>6?"высокая — возможна упаковка":"нормальная";
  results.push({tool:"binwalk",cmd:`binwalk ${fileName}`,output:`Энтропия: ${ent.toFixed(3)}/8.0 (${entLabel})\nРазмер: ${fmtSize(b.length)}`,findings:ent>7.2?[{token:`entropy=${ent.toFixed(2)}`,desc:"Нетипично высокая энтропия. Попробуйте upx -d (UPX-упаковка) или binwalk -e для распаковки."}]:[]});

  return results;
}

function analyzeCrypto(ctx) {
  const {fileName,bytes:b,type,entropy:ent}=ctx;
  const text=toText(b);
  const results=[];

  const entLabel=ent>7.5?"очень высокая — данные зашифрованы":ent>6.5?"высокая — шифрование или сжатие":ent>4?"средняя — структурированные данные":"низкая — открытый текст";
  results.push({tool:"entropy",cmd:`python3 -c "import math,collections; d=open('${fileName}','rb').read(); c=collections.Counter(d); print(sum(-v/len(d)*math.log2(v/len(d)) for v in c.values()))"`,output:`Энтропия Шеннона: ${ent.toFixed(4)} / 8.0\n→ ${entLabel}`,findings:ent>7?[{token:`H=${ent.toFixed(2)}`,desc:"Высокая энтропия: почти случайные данные. Вероятно симметричное шифрование (AES, XOR с ключом, RC4) или сжатие."}]:[]});

  const b64=tryBase64(text.trim());
  const b64flags=b64?findFlags(b64):[];
  results.push({tool:"base64 -d",cmd:`base64 -d ${fileName}`,output:b64!==null?`Успешно!\n${b64.slice(0,300)}${b64.length>300?"…":""}` :"(не похоже на base64)",findings:b64flags.length?b64flags.map(f=>({token:f,desc:"Флаг найден после base64-декодирования!",isFlag:true})):b64!==null?[{token:"base64 OK",desc:"Данные декодированы из base64. Проверьте результат выше."}]:[],highlight:b64flags.length>0});

  const hexd=tryHex(text.trim());
  const hexflags=hexd?findFlags(hexd):[];
  results.push({tool:"hex decode",cmd:`python3 -c "print(bytes.fromhex(open('${fileName}').read().strip()).decode())"`,output:hexd!==null?`Успешно!\n${hexd.slice(0,300)}` :"(не похоже на hex)",findings:hexflags.length?hexflags.map(f=>({token:f,desc:"Флаг найден после hex-декодирования!",isFlag:true})):hexd!==null?[{token:"hex OK",desc:"Данные hex-декодированы."}]:[],highlight:hexflags.length>0});

  if (ent<5.5) {
    const rotted=rot13(text.slice(0,500));
    const rotflags=findFlags(rotted);
    results.push({tool:"ROT13",cmd:`cat ${fileName} | tr 'A-Za-z' 'N-ZA-Mn-za-m'`,output:rotted.slice(0,300),findings:rotflags.map(f=>({token:f,desc:"Флаг найден после ROT13!",isFlag:true})),highlight:rotflags.length>0});
  }

  const rawFlags=findFlags(text);
  if (rawFlags.length) results.push({tool:"grep flag",cmd:`grep -iE '(flag|ctf)\\{' ${fileName}`,output:rawFlags.join("\n"),findings:rawFlags.map(f=>({token:f,desc:"Флаг найден в открытом виде!",isFlag:true})),highlight:true});

  return results;
}

function analyzeOsint(ctx) {
  const {fileName,bytes:b,type}=ctx;
  const text=toText(b);
  const results=[];

  results.push({tool:"file",cmd:`file ${fileName}`,output:`${fileName}: ${type.label}\nРазмер: ${fmtSize(b.length)}`,findings:[]});

  const metaPats=[/GPS[A-Za-z]*[\s:=]+[-\d.]+/gi,/\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}/g,/Make[\s:=]+\w[\w ]{2,30}/gi,/Model[\s:=]+\w[\w .-]{2,30}/gi,/Software[\s:=]+\w[\w .-]{2,40}/gi,/Author[\s:=]+\w[\w .-]{2,40}/gi,/Creator[\s:=]+\w[\w .-]{2,40}/gi,/Comment[\s:=]+[^\x00-\x1f]{4,80}/gi];
  const meta=[];
  for (const p of metaPats) for (const m of (text.match(p)||[])) meta.push(m.trim());
  const exifFindings=[];
  if (meta.some(m=>/gps/i.test(m))) exifFindings.push({token:"GPS coordinates",desc:"Найдены GPS-координаты! Проверьте в Google Maps — могут указывать на место из задания."});
  if (meta.some(m=>/software|creator|author/i.test(m))) exifFindings.push({token:"Software/Creator",desc:"Метаданные создателя файла — может быть подсказкой о личности или инструменте."});
  if (meta.some(m=>/\d{4}:\d{2}:\d{2}/.test(m))) exifFindings.push({token:"Дата создания",desc:"Дата в метаданных — иногда является частью флага или подсказкой."});
  results.push({tool:"exiftool",cmd:`exiftool ${fileName}`,output:meta.slice(0,20).join("\n")||"(метаданные не найдены)",findings:exifFindings,highlight:exifFindings.length>0});

  if (type.type==="PNG") { const i=analyzePNG(b); if(i) results.push({tool:"identify",cmd:`identify -verbose ${fileName}`,output:`PNG ${i.w}×${i.h} px | ${i.color} | ${i.depth} bpp`,findings:[]}); }
  if (type.type==="JPEG") { const i=analyzeJPEG(b); if(i) results.push({tool:"identify",cmd:`identify -verbose ${fileName}`,output:`JPEG ${i.w}×${i.h} px`,findings:[]}); }

  const urls=(text.match(/https?:\/\/[^\s"'<>]{4,80}/g)||[]).slice(0,8);
  const emails=(text.match(/[a-zA-Z0-9._%+-]{2,}@[a-zA-Z0-9.-]{2,}\.[a-zA-Z]{2,}/g)||[]).slice(0,8);
  if (urls.length||emails.length) {
    results.push({tool:"grep URL/Email",cmd:`strings ${fileName} | grep -E "(http|@)"`,output:[...urls,...emails].join("\n"),findings:urls.map(u=>({token:u.slice(0,60),desc:"URL найден — возможно ведёт к следующей части задания."})).concat(emails.map(e=>({token:e,desc:"Email-адрес найден в файле."})))});
  }

  const flags=findFlags(text);
  if (flags.length) results.push({tool:"grep flag",cmd:`strings ${fileName} | grep -i flag`,output:flags.join("\n"),findings:flags.map(f=>({token:f,desc:"Флаг найден в метаданных!",isFlag:true})),highlight:true});

  return results;
}

function analyzeWeb(ctx) {
  const {fileName,bytes:b,type}=ctx;
  const text=toText(b);
  const results=[];

  results.push({tool:"file",cmd:`file ${fileName}`,output:`${fileName}: ${type.label}\nРазмер: ${fmtSize(b.length)}`,findings:[]});

  const secretPats=[
    {re:/password\s*[=:]\s*['"]?([^\s'"<>{}\n]{4,40})/gi,label:"Пароль"},
    {re:/api[_-]?key\s*[=:]\s*['"]?([^\s'"<>{}\n]{8,60})/gi,label:"API ключ"},
    {re:/token\s*[=:]\s*['"]?([^\s'"<>{}\n]{8,60})/gi,label:"Токен"},
    {re:/secret\s*[=:]\s*['"]?([^\s'"<>{}\n]{4,40})/gi,label:"Секрет"},
    {re:/private[_-]?key\s*[=:]\s*['"]?([^\s'"<>{}\n]{8,60})/gi,label:"Приватный ключ"},
  ];
  const secLines=[]; const secFindings=[];
  for (const {re,label} of secretPats) for (const m of (text.match(re)||[]).slice(0,3)) { secLines.push(m.trim().slice(0,80)); secFindings.push({token:label,desc:`Найдено: «${m.trim().slice(0,50)}»`}); }
  results.push({tool:"grep secrets",cmd:`grep -Ei "(password|api_key|token|secret)" ${fileName}`,output:secLines.join("\n")||"(секреты не найдены)",findings:secFindings,highlight:secFindings.length>0});

  const comments=(text.match(/<!--[\s\S]{2,200}?-->|\/\*[\s\S]{2,200}?\*\/|\/\/.{4,120}/g)||[]).slice(0,8);
  const commentFlags=comments.flatMap(c=>findFlags(c));
  results.push({tool:"grep комментарии",cmd:`grep -E "(<!--|//|/\\*)" ${fileName}`,output:comments.join("\n")||"(комментарии не найдены)",findings:commentFlags.map(f=>({token:f,desc:"Флаг в комментарии!",isFlag:true})),highlight:commentFlags.length>0});

  const sqlPats=(text.match(/SELECT\s+.{4,60}FROM\s+\w+|UNION\s+SELECT|' OR '1'='1|DROP\s+TABLE/gi)||[]).slice(0,5);
  if (sqlPats.length) results.push({tool:"grep SQL",cmd:`grep -iE "(SELECT|UNION|DROP|OR 1=1)" ${fileName}`,output:sqlPats.join("\n"),findings:sqlPats.map(s=>({token:s.slice(0,40),desc:"SQL-конструкция — возможна инъекция или схема БД."}))});

  const flags=findFlags(text);
  if (flags.length) results.push({tool:"grep flag",cmd:`grep -i flag ${fileName}`,output:flags.join("\n"),findings:flags.map(f=>({token:f,desc:"Флаг найден!",isFlag:true})),highlight:true});

  const urls=(text.match(/https?:\/\/[^\s"'<>]{4,80}/g)||[]).slice(0,6);
  if (urls.length) results.push({tool:"grep URL",cmd:`grep -oE "https?://[^ ]+" ${fileName}`,output:urls.join("\n"),findings:urls.map(u=>({token:u.slice(0,60),desc:"Внешний URL — возможно ведёт к следующей части задания."}))});

  return results;
}

function analyzePwn(ctx) {
  const {fileName,bytes:b,type}=ctx;
  const results=[];
  const elf=type.type==="ELF"?analyzeELF(b):null;

  let fileOut=`${fileName}: ${type.label}`;
  if (elf) fileOut=`${fileName}: ELF ${elf.bits}-bit ${elf.endian}\n  Архитектура: ${elf.arch}\n  Тип: ${elf.etype}`;
  results.push({tool:"file",cmd:`file ${fileName}`,output:fileOut,findings:[]});

  if (elf) {
    const strs=extractStrings(b,4);
    const hasCanary=strs.some(s=>s.includes("stack_chk")||s.includes("__stack_chk_fail"));
    const secOut=[
      `Stack canary: ${hasCanary?"FOUND (защита стека есть)":"NOT FOUND (защиты нет)"}`,
      `PIE:          ${elf.isPIE?"enabled (ASLR, случайные адреса)":"disabled (фиксированные адреса 0x400000+)"}`,
      `NX:           вероятно enabled (определяется через readelf -W -l)`,
      `Arch:         ${elf.arch}, ${elf.bits}-bit`,
    ].join("\n");
    const secFindings=[];
    if (!hasCanary) secFindings.push({token:"No canary",desc:"Canary не обнаружен — переполнение буфера стека проще эксплуатировать."});
    if (!elf.isPIE) secFindings.push({token:"No PIE",desc:"Фиксированные адреса: .text, .plt, .got известны заранее — удобно для ROP и GOT overwrite."});
    if (hasCanary) secFindings.push({token:"canary detected",desc:"Stack canary присутствует — нужна его утечка для обхода (format string, off-by-one)."});
    results.push({tool:"checksec",cmd:`checksec --file=${fileName}`,output:secOut,findings:secFindings,highlight:secFindings.length>0});

    const dangerous=["gets","strcpy","strcat","sprintf","vsprintf","scanf","system","execve","popen","printf"];
    const foundFuncs=extractStrings(b,3).filter(s=>dangerous.includes(s));
    const hasBinSh=extractStrings(b,4).some(s=>s.includes("/bin/sh")||s.includes("/bin/bash"));
    const funcFindings=foundFuncs.map(f=>{
      const d={gets:"gets() не проверяет длину → классическое BOF.",strcpy:"strcpy() → BOF без проверки длины.",scanf:"scanf(\"%s\") → BOF без ограничения.",system:"system() найден → ret2system: передайте \"/bin/sh\" первым аргументом.",execve:"execve() → вектор для shell.",sprintf:"sprintf() без ограничения → BOF.",printf:"printf() → возможна format string уязвимость (%x, %n)."};
      return {token:`${f}()`,desc:d[f]||`Небезопасная функция ${f}() найдена.`};
    });
    if (hasBinSh) funcFindings.push({token:"/bin/sh",desc:"Строка /bin/sh найдена в бинарнике! Используйте в ret2system: system(\"/bin/sh\")."});
    results.push({tool:"strings + grep",cmd:`strings ${fileName} | grep -E "^(gets|strcpy|scanf|system|execve|printf)$"\nstrings ${fileName} | grep /bin/sh`,output:[...foundFuncs,...(hasBinSh?["/bin/sh - FOUND!"]:["(строка /bin/sh не найдена)"])].join("\n"),findings:funcFindings,highlight:funcFindings.length>0});
  }

  results.push({tool:"xxd",cmd:`xxd ${fileName} | head -16`,output:hexDump(b,6),findings:[]});
  return results;
}

function analyzeForensics(ctx) {
  const {fileName,bytes:b,type,entropy:ent}=ctx;
  const text=toText(b);
  const results=[];

  const ext=fileName.split(".").pop().toLowerCase();
  const typeToExt={PNG:["png"],JPEG:["jpg","jpeg"],GIF:["gif"],ZIP:["zip"],PDF:["pdf"],ELF:["elf","bin",""],PE:["exe","dll","com"]};
  const expected=typeToExt[type.type]||[];
  const mismatch=expected.length&&!expected.includes(ext)?`расширение .${ext} не соответствует типу ${type.type}`:null;
  const fileFindings=mismatch?[{token:"Extension mismatch",desc:`${mismatch} — файл может скрывать своё содержимое!`}]:[];
  results.push({tool:"file",cmd:`file ${fileName}`,output:`${fileName}: ${type.label}\nРазмер: ${fmtSize(b.length)}${mismatch?"\n⚠ ВНИМАНИЕ: "+mismatch:""}`,findings:fileFindings,highlight:!!mismatch});

  results.push({tool:"xxd",cmd:`xxd ${fileName} | head -20`,output:hexDump(b,10),findings:[{token:type.label,desc:"Magic bytes: первые байты определяют истинный тип файла — проверьте соответствие расширению."}]});

  const embedded=findEmbedded(b);
  const embedFindings=embedded.map(e=>({token:`${e.type} @ 0x${e.offset.toString(16)}`,desc:`Встроенный файл ${e.label} по смещению 0x${e.offset.toString(16)}. Извлечение: binwalk -e или dd if=${fileName} bs=1 skip=${e.offset} of=extracted`}));
  results.push({tool:"binwalk",cmd:`binwalk ${fileName}`,output:embedded.length?embedded.map(e=>`0x${e.offset.toString(16).padStart(8,"0")}  ${e.type}  ${e.label}`).join("\n"):"(встроенных файлов не обнаружено)",findings:embedFindings,highlight:embedded.length>0});

  const strs=extractStrings(b,5);
  const flags=findFlags(strs.join("\n"));
  results.push({tool:"strings",cmd:`strings -n 5 ${fileName}`,output:strs.slice(0,30).join("\n")+(strs.length>30?`\n... (ещё ${strs.length-30})`:""),findings:flags.map(f=>({token:f,desc:"Флаг найден в строках!",isFlag:true})),highlight:flags.length>0});

  const entLabel=ent>7.5?"Очень высокая: зашифрован или сжат":ent>5.5?"Высокая: структурированные бинарные данные":"Нормальная";
  results.push({tool:"binwalk -E",cmd:`binwalk -E ${fileName}`,output:`Энтропия: ${ent.toFixed(4)} / 8.0\n→ ${entLabel}`,findings:ent>7.5?[{token:`H=${ent.toFixed(2)}`,desc:"Высокая энтропия во всём файле. Попробуйте распаковать: 7z, zlib.decompress, openssl dec."}]:[]});

  return results;
}

function analyzeStego(ctx) {
  const {fileName,bytes:b,type,entropy:ent}=ctx;
  const results=[];

  const pngI=type.type==="PNG"?analyzePNG(b):null;
  const jpgI=type.type==="JPEG"?analyzeJPEG(b):null;
  const dim=pngI?`${pngI.w}×${pngI.h} px | ${pngI.color} | ${pngI.depth} bpp`:jpgI?`${jpgI.w}×${jpgI.h} px`:"";
  results.push({tool:"file / identify",cmd:`file ${fileName} && identify ${fileName}`,output:`${type.label}${dim?"\n"+dim:""}\nРазмер файла: ${fmtSize(b.length)}`,findings:[]});

  // appended data check
  let tail=null;
  if (type.type==="JPEG") tail=jpegTail(b);
  if (type.type==="PNG") tail=pngTail(b);
  if (tail!==null) {
    const tailType=tail.length>0?detectType(tail):null;
    const tailText=tail.length>0?toText(tail):"";
    const tailFlags=findFlags(tailText);
    const tailFindings=[];
    if (tailType) tailFindings.push({token:tailType.label,desc:`В хвосте обнаружен ${tailType.label}! Сохраните: dd if=${fileName} bs=1 skip=<offset> of=tail_extracted`});
    tailFlags.forEach(f=>tailFindings.push({token:f,desc:"Флаг найден в данных за концом изображения!",isFlag:true}));
    if (!tailFindings.length&&tail.length>0) tailFindings.push({token:`+${tail.length} байт`,desc:"Данные за маркером конца изображения — аномалия! Извлеките и проверьте содержимое."});
    results.push({tool:"binwalk",cmd:`binwalk ${fileName}`,output:tail.length===0?"(данных за концом изображения нет)":`Обнаружено ${tail.length} байт после EOF изображения!\nПервые байты: ${Array.from(tail.slice(0,16)).map(v=>v.toString(16).padStart(2,"0")).join(" ")}${tailType?"\nТип: "+tailType.label:""}`,findings:tailFindings,highlight:tail.length>0});
  }

  const embedded=findEmbedded(b);
  if (embedded.length) {
    results.push({tool:"binwalk -e",cmd:`binwalk -e ${fileName}`,output:embedded.map(e=>`0x${e.offset.toString(16).padStart(8,"0")}  ${e.label}`).join("\n"),findings:embedded.map(e=>({token:`${e.type} @ 0x${e.offset.toString(16)}`,desc:`Встроенный файл: ${e.label}. Запустите binwalk -e для извлечения.`})),highlight:true});
  }

  const strs=extractStrings(b,5);
  const flags=findFlags(strs.join("\n"));
  const meta=strs.filter(s=>/exif|comment|author|software|copyright|gps/i.test(s)).slice(0,8);
  results.push({tool:"strings + exiftool",cmd:`strings ${fileName}\nexiftool ${fileName}`,output:[...flags,...meta].join("\n")||"(строки не найдены)",findings:[...flags.map(f=>({token:f,desc:"Флаг найден в метаданных!",isFlag:true})),...meta.map(m=>({token:m.slice(0,50),desc:"Метаданные изображения — может содержать подсказку."}))],highlight:flags.length>0});

  if (type.type==="PNG"||type.type==="BMP") {
    results.push({tool:"zsteg",cmd:`zsteg -a ${fileName}`,output:`Для LSB-анализа запустите:\n  zsteg -a ${fileName}\n  StegSolve → Bit Planes (R/G/B/A, plane 0–7)\n\nОбращайте внимание на bit plane 0 каждого канала — там чаще всего прячут данные в PNG.`,findings:[{token:"LSB (bit plane 0)",desc:"Стандартная LSB-стеганография в PNG: данные в младших битах пикселей. zsteg автоматически проверяет все комбинации."}]});
  }

  if (type.type==="JPEG") {
    results.push({tool:"steghide",cmd:`steghide extract -sf ${fileName} -p ""\nstegseek ${fileName} /usr/share/wordlists/rockyou.txt`,output:`Попробуйте steghide с пустым паролем, с паролью "password", или брутфорс через stegseek.\nТакже проверьте outguess и jsteg.`,findings:[{token:"steghide passphrase",desc:"JPEG часто используют steghide. Пустой пароль, название задания, или слова из rockyou.txt — частые случаи на CTF."}]});
  }

  if (type.type==="MP3"||type.type==="RIFF"||type.type==="OGG") {
    results.push({tool:"Audacity / sox",cmd:`sox ${fileName} -n spectrogram -o spec.png`,output:`Откройте в Audacity → View → Spectrogram.\nПризнаки стеганографии: видимый текст/QR-код на спектрограмме, аномальные частоты.`,findings:[{token:"spectrogram",desc:"Аудиофайлы часто содержат скрытые сообщения на спектрограмме. Откройте в Audacity и посмотрите спектр (Ctrl+Shift+U)."}]});
  }

  results.push({tool:"entropy",cmd:`python3 -c "import math,collections; d=open('${fileName}','rb').read(); c=collections.Counter(d); print(sum(-v/len(d)*math.log2(v/len(d)) for v in c.values()))"`,output:`Энтропия: ${ent.toFixed(4)} / 8.0\n→ ${ent>7.2?"Нетипично высокая для изображения — вероятно встроенные данные или архив":ent>5?"Нормальная для изображения":"Низкая — простое изображение"}`,findings:ent>7.2?[{token:`H=${ent.toFixed(2)}`,desc:"Высокая энтропия изображения: возможно внутри зашифрованный архив или AES-стеганография."}]:[]});

  return results;
}

function analyzeMisc(ctx) {
  const {fileName,bytes:b,type,entropy:ent}=ctx;
  const text=toText(b);
  const results=[];

  results.push({tool:"file",cmd:`file ${fileName}`,output:`${fileName}: ${type.label}\nРазмер: ${fmtSize(b.length)}\nЭнтропия: ${ent.toFixed(3)}/8.0`,findings:[]});
  results.push({tool:"xxd",cmd:`xxd ${fileName} | head -10`,output:hexDump(b,5),findings:[{token:type.label,desc:"Magic bytes: первые байты определяют формат файла независимо от расширения."}]});

  const b64=tryBase64(text.trim());
  const hxd=tryHex(text.trim());
  const rot=rot13(text.slice(0,300));
  const allDecoded=[b64,hxd,rot].filter(Boolean).join("\n");
  const decFlags=findFlags(allDecoded);
  const decFindings=decFlags.map(f=>({token:f,desc:"Флаг найден после декодирования!",isFlag:true}));
  if (b64) decFindings.push({token:"base64 detected",desc:"Данные похожи на base64-кодирование."});
  const decOut=[`base64: ${b64?"OK → "+b64.slice(0,80):"нет"}`,`hex: ${hxd?"OK → "+hxd.slice(0,80):"нет"}`,`ROT13: ${rot.slice(0,80)}`].join("\n");
  results.push({tool:"decode",cmd:`base64 -d ${fileName}\npython3 -c "import codecs; print(codecs.decode(open('${fileName}').read(),'rot13'))"`,output:decOut,findings:decFindings,highlight:decFlags.length>0});

  const strs=extractStrings(b,5);
  const flags=findFlags(strs.join("\n")+"\n"+text);
  if (flags.length) results.push({tool:"strings / grep flag",cmd:`strings ${fileName} | grep -iE "(flag|ctf)\\{"`,output:flags.join("\n"),findings:flags.map(f=>({token:f,desc:"Флаг найден!",isFlag:true})),highlight:true});
  else results.push({tool:"strings",cmd:`strings -n 5 ${fileName}`,output:strs.slice(0,25).join("\n")||"(строки не найдены)",findings:[]});

  const embedded=findEmbedded(b);
  if (embedded.length) results.push({tool:"binwalk",cmd:`binwalk -e ${fileName}`,output:embedded.map(e=>`0x${e.offset.toString(16).padStart(8,"0")}  ${e.label}`).join("\n"),findings:embedded.map(e=>({token:`${e.type} @ 0x${e.offset.toString(16)}`,desc:`Встроенный файл: ${e.label}`})),highlight:true});

  return results;
}

/* ============================================================
   Recommendation engine
   ============================================================ */
function getSignals(results) {
  const allF = results.flatMap(r => r.findings || []);
  const allOut = results.map(r => r.output || "").join("\n");
  const entM = allOut.match(/Энтропия[:\s]+(\d+\.\d+)/);
  const entV = entM ? parseFloat(entM[1]) : 0;
  const fileOut = (results.find(r => r.tool==="file"||r.tool==="file / identify")?.output)||"";
  let ft = "BINARY";
  if (fileOut.includes("ELF")) ft="ELF";
  else if (fileOut.includes("PE исполняемый")) ft="PE";
  else if (fileOut.includes("PNG")) ft="PNG";
  else if (fileOut.includes("JPEG")) ft="JPEG";
  else if (fileOut.includes("GIF")) ft="GIF";
  else if (fileOut.includes("BMP")) ft="BMP";
  else if (fileOut.includes("ZIP")) ft="ZIP";
  else if (fileOut.includes("RAR")) ft="RAR";
  else if (fileOut.includes("PDF")) ft="PDF";
  else if (fileOut.includes("Текстовый")) ft="TEXT";
  else if (fileOut.includes("SQLite")) ft="SQLITE";
  else if (fileOut.includes("OGG")||fileOut.includes("MP3")||fileOut.includes("RIFF")) ft="AUDIO";
  return {
    flags:        allF.filter(f=>f.isFlag).map(f=>f.token),
    entropy:      entV,
    highEnt:      entV > 7.2,
    midEnt:       entV >= 5 && entV <= 7.2,
    lowEnt:       entV > 0 && entV < 5,
    fileType:     ft,
    isELF:        ft==="ELF",
    isPE:         ft==="PE",
    isImage:      ["PNG","JPEG","GIF","BMP"].includes(ft),
    isAudio:      ft==="AUDIO",
    isZip:        ft==="ZIP"||ft==="RAR",
    isText:       ft==="TEXT",
    // ELF/PWN
    isPIE:        allF.some(f=>f.token==="PIE/DYN"),
    noPIE:        allF.some(f=>f.token==="No PIE"),
    noCanary:     allF.some(f=>f.token==="No canary"),
    hasCanary:    allF.some(f=>f.token?.includes("canary detected")),
    hasBinSh:     allOut.includes("/bin/sh - FOUND"),
    hasSystem:    allF.some(f=>f.token==="system()"),
    hasGets:      allF.some(f=>f.token==="gets()"),
    hasScanf:     allF.some(f=>f.token==="scanf()"),
    hasPrintf:    allF.some(f=>f.token==="printf()"),
    hasStrcpy:    allF.some(f=>f.token==="strcpy()"),
    bits64:       fileOut.includes("64-bit"),
    // crypto
    b64OK:        results.some(r=>r.tool==="base64 -d"&&r.output?.includes("Успешно")),
    hexOK:        results.some(r=>r.tool==="hex decode"&&r.output?.includes("Успешно")),
    rotFlag:      results.some(r=>r.tool==="ROT13"&&r.findings?.some(f=>f.isFlag)),
    // forensics/stego
    hasTail:      allOut.match(/Обнаружено \d+ байт после/),
    hasEmbedded:  results.some(r=>r.tool?.startsWith("binwalk")&&r.highlight&&r.findings?.length>0),
    embeds:       results.filter(r=>r.tool?.startsWith("binwalk")&&r.highlight).flatMap(r=>r.findings||[]).map(f=>f.token),
    extMismatch:  allF.some(f=>f.token==="Extension mismatch"),
    // osint/web
    hasGPS:       allF.some(f=>f.token==="GPS coordinates"),
    hasURLs:      results.some(r=>r.tool?.includes("URL")&&r.findings?.length>0),
    hasSecrets:   results.some(r=>r.tool==="grep secrets"&&r.highlight),
    hasComments:  results.some(r=>r.tool?.includes("комментарии")&&r.highlight),
  };
}

function r(priority, title, steps, commands=[]) {
  return {priority, title, steps, commands};
}

function recReverse(s, recs) {
  if (s.highEnt) {
    recs.push(r("high","Файл упакован или зашифрован — распакуйте его первым делом",
      ["Высокая энтропия (>7.2/8.0) означает пакер (UPX — самый распространённый в CTF) или произвольное шифрование. Ghidra и IDA покажут только распакованный стаб — пользы ноль.",
       "Сначала попробуйте upx -d. Если не сработало — запускайте бинарник под GDB, дожидайтесь самораспаковки в памяти, затем сохраняйте дамп процесса (process_vm_readv / gcore)."],
      ["upx -d ./binary","binwalk -e ./binary  # автоматическое извлечение","# Если ни то ни другое — динамика:","gdb ./binary  →  break main  →  run  →  dump memory dump.bin 0xADDR 0xEND"]
    ));
  }
  if (s.isELF && !s.highEnt) {
    recs.push(r("high","Откройте в Ghidra и найдите логику проверки флага",
      ["ELF с нормальной энтропией готов к статическому анализу. Ориентиры: функции с именами check, validate, compare, verify или просто main.",
       "Ищите вызовы strcmp / strncmp / memcmp — одна из сторон почти всегда является хранимым флагом или ключом. В декомпиляторе Ghidra это выглядит как strcmp(input, \"flag{...}\").",
       "Если файл stripped (нет символов) — используйте Function Identify (FI): Help → Analyze → Function ID, чтобы восстановить имена libc-функций."],
      ["ghidra &","# В Ghidra: File → New Project → Import File → Analyze → Go to Symbol Tree → Functions"]
    ));
    recs.push(r("medium","Параллельно запустите под GDB для динамического анализа",
      ["GDB + Pwndbg позволяет поставить breakpoint прямо перед strcmp и увидеть оба аргумента в регистрах rdi/rsi (x64) или [esp+4]/[esp+8] (x86).",
       "Удобная стратегия: введите любой ввод, дождитесь «Wrong password» → поищите в дизассемблере откуда пришло это строковое сравнение → ставьте break на ту функцию."],
      ["gdb -q ./binary","(gdb) catch syscall exit  # остановиться перед выходом","(gdb) run <<< 'AAAA'","# В pwndbg: retrace / nearpc / x/s $rdi"]
    ));
  }
  if (s.isPE) {
    recs.push(r("high","PE (Windows): порядок действий — DiE → Ghidra → x64dbg",
      ["1. Detect-it-Easy (DiE) — проверить пакер/протектор. Если есть — убрать сначала.",
       "2. Ghidra или IDA Free — декомпиляция, поиск WinAPI-вызовов (GetDlgItemText, MessageBox, CompareString).",
       "3. x64dbg — динамика: F2 на нужную функцию, F7/F8 для прохода по инструкциям, правая кнопка → Follow in Dump для просмотра строк."],
      ["# На Linux: wine ./crackme.exe","# Или запустите в Windows-VM с x64dbg"]
    ));
  }
}

function recCrypto(s, recs) {
  if (s.b64OK) {
    recs.push(r("high","base64 успешно декодировано — что внутри?",
      ["Сохраните декодированный результат в файл и определите его тип. В CTF часто встречается многоуровневое кодирование: base64 → hex → base32 → ROT → флаг.",
       "Если результат — бинарный файл, запустите file decoded и продолжайте анализ."],
      ["base64 -d input.txt > decoded","file decoded","xxd decoded | head -4  # проверить magic bytes","# Ещё уровни? Повторите base64 -d / xxd / python3 / CyberChef"]
    ));
  }
  if (s.hexOK) {
    recs.push(r("high","HEX декодирован — продолжайте анализ результата",
      ["HEX-строка успешно декодирована. Проверьте что получилось: ещё одна кодировка? бинарный файл? читаемый текст?"],
      ["python3 -c \"open('out','wb').write(bytes.fromhex(open('in').read().strip()))\"","file out  # определить тип результата"]
    ));
  }
  if (s.highEnt && !s.b64OK && !s.hexOK && !s.flags.length) {
    recs.push(r("high","Высокая энтропия — данные зашифрованы, нужно определить алгоритм",
      ["Вопросы для определения алгоритма:\n  • Размер файла кратен 16? → скорее всего AES (CBC или ECB)\n  • Файл начинается с 'Salted__' (ASCII)? → openssl enc формат\n  • Длина ключа намекается в задании? → подбор по длине\n  • Есть повторяющиеся 16-байтные блоки? → ECB-режим (атака на паттерны)",
       "XOR с коротким ключом — самый частый вариант в начальных CTF-задачах. xortool автоматически определяет длину ключа по частотному анализу."],
      ["xortool encrypted.bin  # анализ XOR-ключа","xortool -x -l KEY_LEN -c 20 encrypted.bin","# AES через openssl:","openssl enc -d -aes-256-cbc -in enc.bin -out dec.bin -pass pass:PASSWORD","# Проверить повторы блоков:","python3 -c \"d=open('f','rb').read(); bl=[d[i:i+16] for i in range(0,len(d),16)]; print(len(bl)-len(set(bl)),'дублей из',len(bl))\""]
    ));
  }
  if (s.lowEnt && !s.flags.length && !s.b64OK) {
    recs.push(r("high","Низкая энтропия — вероятно классический шифр замены",
      ["Текст с низкой энтропией почти всегда означает шифр замены (Caesar, ROT13, Vigenère, Atbash) или транспозицию.",
       "Стратегия: CyberChef (Magic operation автоматически перебирает варианты) → dcode.fr → ручной анализ по частотам букв."],
      ["# Caesar brute force:","python3 -c \"t=open('f').read(); [print(i,''.join(chr((ord(c)-65+i)%26+65)if c.isupper()else chr((ord(c)-97+i)%26+97)if c.islower()else c for c in t)) for i in range(1,26)]\"","# Vigenère — Kasiski test онлайн: https://www.dcode.fr/vigenere-cipher"]
    ));
  }
}

function recOsint(s, recs) {
  if (s.hasGPS) {
    recs.push(r("critical","Найдены GPS-координаты — проверьте местоположение",
      ["Координаты в метаданных могут указывать на место, связанное с заданием: офис компании, достопримечательность, конкретное здание.",
       "Откройте координаты в Google Maps/Street View. Иногда задание требует указать название места или найти что-то на фото с этого адреса."],
      ["exiftool -GPSLatitude -GPSLongitude -GPSAltitude photo.jpg","# Конвертировать DMS → DD: например 55°45'30\"N = 55 + 45/60 + 30/3600 = 55.7583"]
    ));
  }
  if (s.hasURLs) {
    recs.push(r("high","Найдены URL — посетите и проанализируйте",
      ["URL в метаданных или теле файла может вести к: скрытой части задания, следующему флагу, исходным данным для расшифровки.",
       "Проверьте Wayback Machine для удалённых страниц. Иногда URL ведёт к нерабочему сервису — ищите кэш."],
      ["# Сохранить страницу:","wget -m [URL]","# Проверить архив:","curl 'https://archive.org/wayback/available?url=[URL]'"]
    ));
  }
  if (!s.hasGPS && !s.flags.length) {
    recs.push(r("high","Расширьте поиск метаданных и связанных данных",
      ["Если exiftool не дал результатов — попробуйте глубже:\n  • Reverse image search (TinEye / Google Images) — источник и история фото\n  • Steganography в изображениях: попробуйте Stego (раздел Стеганография)\n  • Поиск по username/email из метаданных в соцсетях\n  • Shodan/Censys для IP-адресов из файла"],
      ["exiftool -all= -tagsfromfile @ -all:all input.jpg  # убрать данные","# Если изображение — попробуйте reverse image search","python3 -c \"from PIL import Image; img=Image.open('f'); print(img.info)\""]
    ));
  }
}

function recWeb(s, recs) {
  if (s.hasSecrets) {
    recs.push(r("critical","Найдены credentials/токены — попробуйте применить",
      ["Найденные пароли, токены и API-ключи — первое что нужно проверить. Попробуйте их:\n  • Как пароль к другим файлам или архивам в задании\n  • Как JWT токен (вставьте на jwt.io для анализа payload)\n  • Как ключ для расшифровки другого файла\n  • Как пароль к форме на целевом сайте"],
      ["# JWT анализ:","python3 -c \"import base64,json; t='TOKEN'.split('.'); print(json.loads(base64.b64decode(t[1]+'==')))\""," # hashcat для взлома хеша:","hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt"]
    ));
  }
  if (s.hasComments) {
    recs.push(r("high","Флаг или подсказка в комментариях — внимательно прочитайте",
      ["Разработчики часто оставляют TODO, закомментированный код с credentials, пути к файлам, и временные флаги в HTML/JS-комментариях.",
       "Просмотрите все комментарии — ищите <!--flag-->, //TODO: remove this password, /* test: admin/admin123 */."],
      ["grep -n '<!--\\|//\\|/\\*' file.html | head -50","# Рекурсивно по всем файлам:","grep -rn 'password\\|TODO\\|FIXME\\|flag' ./webapp/"]
    ));
  }
  if (!s.hasSecrets && !s.hasComments && !s.flags.length) {
    recs.push(r("high","Изучите структуру веб-приложения глубже",
      ["Ручной анализ даст больше чем автоматический. Что искать:\n  1. Скрытые параметры: добавьте ?debug=1, ?admin=true, ?id=0\n  2. LFI: ?file=../../../../etc/passwd\n  3. Исходный код в JS: webpack chunks часто содержат API endpoints\n  4. Заголовки HTTP: X-Custom-Header, Set-Cookie с интересными значениями\n  5. robots.txt и .htaccess — скрытые пути"],
      ["# Просмотр всех JS-файлов на странице:","curl -s [URL] | grep -oE 'src=\"[^\"]+\\.js\"'","# Fuzzing директорий:","ffuf -w /usr/share/wordlists/dirb/common.txt -u [URL]/FUZZ","# Nikto сканирование:","nikto -h [URL]"]
    ));
  }
}

function recPwn(s, recs) {
  if (s.noCanary && s.noPIE) {
    recs.push(r("critical","Нет canary + нет PIE — классическое переполнение буфера",
      ["Идеальные условия для ret2win или ret2system атаки. Адреса секций фиксированы, защиты стека нет.",
       "Определите размер буфера до ret-адреса: создайте паттерн (cyclic 200), запустите, найдите смещение по значению RIP/EIP в момент segfault."],
      ["# Создать паттерн (pwndbg/pwntools):","python3 -c \"from pwn import *; print(cyclic(200))\" > input","gdb ./binary  →  run < input  →  (после segfault): cyclic -l $rsp","# Найти адрес win-функции:","objdump -d ./binary | grep 'win\\|shell\\|flag'","readelf -s ./binary | grep -i 'win\\|flag'"]
    ));
  }
  if (s.noCanary && s.isPIE) {
    recs.push(r("high","Нет canary, но есть PIE — нужна утечка адреса",
      ["BOF возможен, но адреса рандомизированы (ASLR + PIE). Нужна утечка (leak) базового адреса образа или libc.",
       "Типичные векторы утечки: format string (%p.%p.%p), чтение за границей буфера (read(0, buf, 1000)), вывод неинициализированной памяти."],
      ["# Найти гаджеты для leak:","ROPgadget --binary ./binary | grep 'pop rdi'","# pwntools шаблон:","# p = process('./binary')","# p.sendline(b'%7$p')  # format string leak","# leak = int(p.recv(), 16)","# base = leak - KNOWN_OFFSET"]
    ));
  }
  if (s.hasCanary && s.noPIE) {
    recs.push(r("high","Есть canary, нет PIE — нужно обойти canary",
      ["Canary защищает стек, но адреса фиксированы. Варианты обхода:\n  1. Format string: %n-й аргумент printf прочитает canary со стека (%41$p для типичных задач)\n  2. Heap overflow / off-by-one в соседний буфер на стеке\n  3. Brute force (только если fork() — у дочернего процесса тот же canary)"],
      ["# Проверить наличие format string:","echo '%p.%p.%p.%p.%p.%p' | ./binary","# Найти позицию canary на стеке (pwndbg):","(gdb) canary  # показывает текущее значение","(gdb) stack 30  # показывает весь стек"]
    ));
  }
  if (s.hasBinSh || s.hasSystem) {
    recs.push(r("high","Найден system() и/или /bin/sh — ret2system атака",
      ["Это самый простой вариант: передать строку \"/bin/sh\" как первый аргумент в system().",
       "x64: аргументы через регистры → нужен gadget 'pop rdi; ret', адрес строки /bin/sh в libc или в .rodata, затем адрес system().",
       "x86: аргументы через стек → [ret addr system] [fake ret] [ptr to /bin/sh]"],
      ["# Адрес /bin/sh в libc:","python3 -c \"import ctypes; l=ctypes.CDLL('libc.so.6'); print(hex(l.system + (next(b'address in libc'))))",  "# Через pwntools:","# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')","# bin_sh = next(libc.search(b'/bin/sh'))","# system = libc.sym['system']"]
    ));
  }
  if (s.hasGets || s.hasStrcpy || s.hasScanf) {
    recs.push(r("medium","Опасные функции — определите размер буфера",
      ["Найдены функции без проверки длины. Определите размер буфера до сохранённого return address (обычно [buffer + rbp + ret]).",
       "В Ghidra: найдите объявление буфера в декомпиляторе — он покажет char buf[SIZE]. Прибавьте 8 (saved rbp) = offset до ret."],
      ["# Паттерн для определения offset:","python3 -c \"from pwn import *; print(cyclic(300).decode())\" | ./binary","# После segfault в pwndbg:","# cyclic -l VALUE_OF_RIP"]
    ));
  }
  if (s.hasPrintf) {
    recs.push(r("medium","Найден printf() — проверьте format string уязвимость",
      ["Если программа делает printf(user_input) вместо printf(\"%s\", user_input) — это format string уязвимость.",
       "Попробуйте ввести: %p%p%p%p%p%p%p%p → если вернулись адреса (0x7ffXXX) — уязвимость есть.",
       "%n позволяет записать произвольное значение по адресу → overwrite GOT / ret addr."],
      ["echo '%p.%p.%p.%p.%p.%p.%p.%p' | ./binary","# Если утечка есть — fmtstr_payload из pwntools:","# from pwn import *; fmtstr_payload(offset, {target_addr: value})"]
    ));
  }
}

function recForensics(s, recs) {
  if (s.extMismatch) {
    recs.push(r("critical","Расширение не совпадает с реальным типом файла",
      ["Файл скрывает своё содержимое за ложным расширением. Определили реальный тип по magic bytes — откройте соответствующим инструментом.",
       "Например: файл с расширением .jpg но содержимое ZIP → переименуйте в .zip и откройте архивом."],
      ["# Переименовать по реальному типу и открыть:","file disguised.jpg  # покажет настоящий тип","mv disguised.jpg disguised.zip && unzip disguised.zip"]
    ));
  }
  if (s.hasEmbedded) {
    recs.push(r("high","Найдены встроенные файлы — извлеките и проанализируйте каждый",
      ["binwalk обнаружил файлы внутри файла. Это типичная CTF-техника: ZIP внутри JPEG, исполняемый файл в дампе памяти, и т.д.",
       "После извлечения — запустите анализ на каждом найденном файле: file, strings, xxd."],
      ["binwalk -e --dd='.*' target_file  # извлечь всё","ls _target_file.extracted/  # посмотреть что нашлось","# Или вручную через dd:","dd if=target_file bs=1 skip=OFFSET of=extracted_file"]
    ));
  }
  if (s.highEnt && !s.hasEmbedded) {
    recs.push(r("high","Весь файл с высокой энтропией — попробуйте расшифровать или распаковать",
      ["Если нет сигнатур известных форматов — данные либо зашифрованы, либо используют нестандартный формат.",
       "Ищите подсказки в названии файла, описании задания или в других файлах того же задания — обычно ключ или алгоритм указан где-то рядом."],
      ["# Попробовать известные форматы:","zlib-flate -uncompress < file.bin > out  # zlib","openssl zlib -d -in file.bin -out out  # gzip/zlib через openssl","python3 -c \"import zlib; open('out','wb').write(zlib.decompress(open('file.bin','rb').read()))\""]
    ));
  }
  if (!s.extMismatch && !s.hasEmbedded && !s.flags.length) {
    recs.push(r("medium","Углублённый анализ: timelines, deleted files, filesystem artefacts",
      ["Если поверхностный анализ ничего не дал — ищите скрытые артефакты:\n  1. Удалённые файлы: Autopsy → Deleted Files, или photorec\n  2. Дамп памяти: Volatility — pslist, filescan, cmdline, hashdump\n  3. Временна́я шкала: mactime / plaso для построения timeline событий\n  4. Скрытые потоки NTFS: streams.exe или Autopsy → Data Artifacts → NTFS Streams"],
      ["# Volatility для дампа памяти:","python3 vol.py -f mem.dmp windows.pslist","python3 vol.py -f mem.dmp windows.cmdline","python3 vol.py -f mem.dmp windows.filescan | grep -i flag","# Восстановление файлов:","photorec target_disk.img"]
    ));
  }
}

function recStego(s, recs) {
  if (s.hasTail) {
    recs.push(r("critical","Данные после конца изображения — обязательно извлеките",
      ["За маркером конца изображения (JPEG: FFD9, PNG: IEND) обнаружены байты. Это самая частая техника в CTF-стегано: файл прячется в «хвосте».",
       "Определите точное смещение через binwalk, затем вырежьте хвост командой dd. Проверьте тип результата — это может быть ZIP, TXT, другое изображение."],
      ["binwalk target.jpg  # найти offset после FFD9/IEND","dd if=target.jpg bs=1 skip=OFFSET of=hidden_data","file hidden_data  # определить тип","# Если ZIP — просто: unzip target.jpg"]
    ));
  }
  if (s.hasEmbedded) {
    recs.push(r("high","Встроенные файлы найдены — извлеките через binwalk",
      ["Внутри изображения/аудио обнаружены сигнатуры других файлов. Чаще всего это ZIP-архив (иногда с паролем) или второе изображение."],
      ["binwalk -e target_file","ls _target_file.extracted/","# Если найден запаролированный ZIP:","fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt hidden.zip","# Или попробуйте пустой пароль:","unzip -P '' hidden.zip"]
    ));
  }
  if (s.fileType==="PNG"||s.fileType==="BMP") {
    if (!s.hasTail && !s.hasEmbedded) {
      recs.push(r("high","PNG/BMP без явных встроенных данных — проверьте LSB",
        ["zsteg проверяет все комбинации LSB-каналов автоматически. Если результат содержит читаемый текст — это ответ.",
         "В StegSolve вручную просматривайте каждую битовую плоскость (Image Combiner → Bit plane 0 для R, G, B, A).",
         "Обратите внимание на planeR0 (Least Significant Bit of Red channel) — наиболее частая скрытность."],
        ["zsteg -a target.png  # автоматический перебор","zsteg -E 'b1,rgb,lsb,xy' target.png | xxd | head  # конкретный канал","# Альтернатива через Python:","python3 -c \"from PIL import Image; img=Image.open('f'); px=list(img.getdata()); print(bytes([p[0]&1 for p in px[:200]]))\""]
      ));
    }
  }
  if (s.fileType==="JPEG") {
    if (!s.hasTail && !s.hasEmbedded) {
      recs.push(r("high","JPEG без явных артефактов — проверьте steghide и outguess",
        ["steghide — самый популярный инструмент для JPEG-стеганографии в CTF. Попробуйте пустой пароль, название задания, 'password', 'stego'.",
         "stegseek работает как hashcat для steghide: автоматически перебирает rockyou.txt за секунды."],
        ["steghide extract -sf target.jpg -p ''  # пустой пароль","stegseek target.jpg /usr/share/wordlists/rockyou.txt","outguess -r target.jpg output.txt","jsteg reveal target.jpg output  # инструмент jsteg"]
      ));
    }
  }
  if (s.isAudio) {
    recs.push(r("high","Аудиофайл — откройте спектрограмму в Audacity",
      ["Самый частый метод в аудио-стегано: текст, QR-код или изображение видны на спектрограмме (частотно-временной диаграмме).",
       "Audacity: откройте файл → в треке нажмите на стрелку рядом с именем → Spectrogram → View → Zoom to fit. Ищите читаемые символы в высокочастотной части.",
       "DTMF тоны (телефонные цифры) можно декодировать через multimon-ng или онлайн."],
      ["# Спектрограмма через sox:","sox audio.wav -n spectrogram -o spec.png","open spec.png  # или eog spec.png","# DTMF декодирование:","multimon-ng -t wav -a DTMF audio.wav"]
    ));
  }
}

function recMisc(s, recs) {
  if (s.b64OK || s.hexOK) {
    recs.push(r("high","Кодирование обнаружено — проверьте результат на вложенность",
      ["В Misc-заданиях часто несколько слоёв кодирования. После первого декодирования снова проверьте: base64? hex? бинарник?",
       "CyberChef → Magic operation автоматически определяет и снимает несколько слоёв."],
      ["base64 -d file | base64 -d | base64 -d  # если несколько слоёв","# CyberChef онлайн: https://gchq.github.io/CyberChef/ → Magic"]
    ));
  }
  if (s.isELF || s.isPE) {
    recs.push(r("medium","Исполняемый файл — запустите в изолированной среде",
      ["Прежде чем анализировать статически — запустите и посмотрите что программа делает и что просит. Иногда флаг выводится при правильном вводе."],
      ["# В docker для изоляции:","docker run --rm -v $(pwd):/work ubuntu:22.04 /work/binary","# Или strace для отслеживания системных вызовов:","strace ./binary 2>&1 | grep -E '(read|write|open)'"]
    ));
  }
  if (!s.flags.length && !s.highEnt) {
    recs.push(r("medium","Ничего очевидного — попробуйте нестандартные кодировки",
      ["Misc-задания часто используют эзотерические кодировки: Brainfuck, Malbolge, JSFuck, WhiteSpace (невидимые пробелы), Braille, Morse, бинарный ASCII.",
       "Если файл выглядит как случайные символы — попробуйте CyberChef → Magic, или manually ищите паттерны длин слов (Morse dot/dash)."],
      ["# Проверить whitespace-стеганографию:","cat -A file.txt  # $ в конце строк, ^I для табов","# Числа 0/1 → ASCII:","python3 -c \"t='01000110...'; print(''.join(chr(int(t[i:i+8],2)) for i in range(0,len(t),8)))\""]
    ));
  }
}

function recommend(catId, results) {
  const s = getSignals(results);
  const recs = [];

  // Universal: flag found
  if (s.flags.length) {
    recs.unshift(r("critical",
      "Возможный флаг найден — введите в форму задания прямо сейчас",
      ["Обнаруженный паттерн:\n  " + s.flags.join("\n  "),
       "Если не принимается — это может быть fake flag или промежуточный результат. Продолжайте анализ, возможно нужна дополнительная обработка (XOR, смещение, reverse string)."],
      []
    ));
  }

  switch (catId) {
    case "reverse":   recReverse(s, recs); break;
    case "crypto":    recCrypto(s, recs); break;
    case "osint":     recOsint(s, recs); break;
    case "web":       recWeb(s, recs); break;
    case "pwn":       recPwn(s, recs); break;
    case "forensics": recForensics(s, recs); break;
    case "stego":     recStego(s, recs); break;
    default:          recMisc(s, recs); break;
  }

  // Always add: if no specific recs, give generic advice
  if (recs.length === 0) {
    recs.push(r("medium","Запустите полный анализ вручную",
      ["Автоматический анализ не выявил явных зацепок. Рекомендуем:\n  1. Внимательно прочитайте описание задания — там часто есть намёки на метод\n  2. Попробуйте CyberChef → Magic operation\n  3. Спросите подсказку у организаторов (hint) если доступно\n  4. Поищите похожие задания на CTFtime.org writeups"],
      ["# CyberChef для автоматического определения кодировки:","# https://gchq.github.io/CyberChef/ → Magic"]
    ));
  }

  return recs;
}

/* ---- public API ---- */
return {
  analyze(catId, fileName, arrayBuffer) {
    const b=new Uint8Array(arrayBuffer);
    const type=detectType(b);
    const ent=entropy(b);
    const ctx={fileName, bytes:b, type, entropy:ent};
    switch(catId) {
      case "reverse":   return analyzeReverse(ctx);
      case "crypto":    return analyzeCrypto(ctx);
      case "osint":     return analyzeOsint(ctx);
      case "web":       return analyzeWeb(ctx);
      case "pwn":       return analyzePwn(ctx);
      case "forensics": return analyzeForensics(ctx);
      case "stego":     return analyzeStego(ctx);
      default:          return analyzeMisc(ctx);
    }
  },
  recommend(catId, results) {
    return recommend(catId, results);
  }
};

})();
