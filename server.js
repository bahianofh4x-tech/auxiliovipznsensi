const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOST = '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const ACCESS_PORT = '777';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SEED_FILE = path.join(__dirname, 'licenses_seed.json');
const DATA_FILE = path.join(__dirname, 'licenses_data.json');
const USERS = new Set(['DELÍRIO7', 'CREUDA063', 'NAEL88']);

function cloneSeed() {
  return JSON.parse(fs.readFileSync(SEED_FILE, 'utf8'));
}
function saveDb(db) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmp, DATA_FILE);
}
function loadDb() {
  if (!fs.existsSync(DATA_FILE)) {
    const seed = cloneSeed();
    const db = { version: 2, licenses: {} };
    for (const item of seed.licenses) db.licenses[item.hash] = {
      duration_days: item.duration_days,
      status: 'unused', activated_at: null, expires_at: null,
      activated_ip: null, activated_by: null
    };
    saveDb(db);
    return db;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    const seed = cloneSeed();
    const db = { version: 2, licenses: {} };
    for (const item of seed.licenses) db.licenses[item.hash] = {
      duration_days: item.duration_days, status: 'unused', activated_at: null,
      expires_at: null, activated_ip: null, activated_by: null
    };
    saveDb(db);
    return db;
  }
}
const db = loadDb();

function normalizeIp(ip) { return String(ip || '').replace(/^::ffff:/, ''); }
function keyHash(key) { return crypto.createHash('sha256').update(key, 'utf8').digest('hex'); }
function clientIp(req) { return normalizeIp(req.socket.remoteAddress); }
function expireOld() {
  let changed = false;
  const now = Date.now();
  for (const lic of Object.values(db.licenses)) {
    if (lic.status === 'active' && lic.expires_at && Date.parse(lic.expires_at) <= now) {
      lic.status = 'expired'; changed = true;
    }
  }
  if (changed) saveDb(db);
}
function json(res,status,data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type','Cache-Control':'no-store'});
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve,reject)=>{
    let data='';
    req.on('data',c=>{ data+=c; if(data.length>16384){ req.destroy(); reject(new Error('Body too large')); }});
    req.on('end',()=>{ try{resolve(data?JSON.parse(data):{});}catch{reject(new Error('JSON inválido'));} });
    req.on('error',reject);
  });
}
function type(file) {
  const ext=path.extname(file).toLowerCase();
  return ({'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8'})[ext] || 'application/octet-stream';
}
function serve(req,res) {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, `http://${HOST}:${PORT}`).pathname); } catch { return json(res,400,{error:'URL inválida'}); }
  if(pathname==='/') pathname='/index.html';
  const file=path.normalize(path.join(PUBLIC_DIR,pathname));
  if(!file.startsWith(PUBLIC_DIR+path.sep)) return json(res,403,{error:'Forbidden'});
  fs.readFile(file,(err,data)=>{ if(err) return json(res,404,{error:'Not found'}); res.writeHead(200,{'Content-Type':type(file),'Cache-Control':'no-store'}); res.end(data); });
}

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS') return json(res,204,{});

  if(req.method==='GET' && (req.url==='/api/health' || req.url==='/healthz')) {
    return json(res,200,{ok:true,service:'ZN SENSI',http_port:PORT,access_port:ACCESS_PORT,keys:Object.keys(db.licenses).length});
  }
  if(req.method==='POST' && req.url==='/api/login') {
    expireOld();
    let body; try{body=await readBody(req);}catch(e){return json(res,400,{ok:false,error:e.message});}
    const username=String(body.username||'').trim().toUpperCase();
    const port=String(body.port||'').trim();
    const rawKey=String(body.key||'').trim();
    const system=String(body.system||'').trim().toUpperCase();
    if(port!==ACCESS_PORT) return json(res,401,{ok:false,error:'Porta inválida.'});
    if(!['IOS','ANDROID','PC'].includes(system)) return json(res,400,{ok:false,error:'Selecione um sistema.'});
    if(!USERS.has(username)) return json(res,401,{ok:false,error:'Usuário não autorizado.'});
    const license=db.licenses[keyHash(rawKey)];
    if(!license) return json(res,401,{ok:false,error:'Key inválida.'});
    if(license.status==='expired') return json(res,403,{ok:false,error:'Esta key já expirou e não pode ser reativada.'});
    const ip=clientIp(req);
    if(license.status==='active' && license.duration_days===1 && license.activated_ip!==ip) return json(res,403,{ok:false,error:'Esta key de 1 dia está vinculada ao IP de ativação.'});
    if(license.status==='unused') {
      const now=new Date();
      license.status='active'; license.activated_at=now.toISOString();
      license.expires_at=new Date(now.getTime()+license.duration_days*86400000).toISOString();
      license.activated_ip=ip; license.activated_by=username; saveDb(db);
    }
    if(Date.parse(license.expires_at)<=Date.now()) { license.status='expired'; saveDb(db); return json(res,403,{ok:false,error:'Esta key expirou.'}); }
    const ms=Math.max(0,Date.parse(license.expires_at)-Date.now());
    return json(res,200,{ok:true,username,system,expires_at:license.expires_at,days_remaining:Math.ceil(ms/86400000)});
  }
  if(req.method==='GET') return serve(req,res);
  return json(res,404,{ok:false,error:'Not found'});
});

server.on('error',err=>{ console.error('ERRO AO INICIAR SERVIDOR:',err.message); process.exitCode=1; });
server.listen(PORT,HOST,()=>{
  console.log('========================================');
  console.log('       ZN SENSI - SERVIDOR ONLINE');
  console.log('========================================');
  console.log(`Painel: http://${HOST}:${PORT}`);
  console.log(`Porta de acesso: ${ACCESS_PORT}`);
  console.log(`Licenças carregadas: ${Object.keys(db.licenses).length}`);
});
