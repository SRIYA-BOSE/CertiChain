'use strict';
require('dotenv').config();
const express=require('express'),cors=require('cors'),helmet=require('helmet'),session=require('express-session');
const multer=require('multer'),crypto=require('crypto'),fs=require('fs'),path=require('path'),bcrypt=require('bcryptjs'),QR=require('qrcode');
const {Gateway,Wallets}=require('fabric-network');
const db=require('./config/db');
const {requireAuth,requireAdmin}=require('./middleware/auth');
const app=express(),PORT=Number(process.env.PORT||3000);
const CHANNEL=process.env.FABRIC_CHANNEL||'mychannel',CHAINCODE=process.env.FABRIC_CHAINCODE||'certichain';
const ORG=process.env.FABRIC_ORG_PATH||path.resolve(__dirname,'../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com');
const CCP=process.env.FABRIC_CCP_PATH||path.join(ORG,'connection-org1.json');
const WALLET=process.env.FABRIC_WALLET_PATH||path.join(__dirname,'wallet');
const STORE=path.join(__dirname,'storage','certificates');
app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:true,credentials:true}));
app.use(express.json({limit:'1mb'}));
app.use(session({name:'certichain.sid',secret:process.env.SESSION_SECRET||'CHANGE_THIS_SESSION_SECRET',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}}));
app.use('/admin',express.static(path.resolve(__dirname,'../frontend/admin')));
app.use('/student',express.static(path.resolve(__dirname,'../frontend/student')));
app.use('/verify',express.static(path.resolve(__dirname,'../frontend/public')));
app.use('/assets',express.static(path.resolve(__dirname,'../frontend/assets')));
app.use('/',express.static(path.resolve(__dirname,'../frontend')));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:8*1024*1024},fileFilter:(req,f,cb)=>f.mimetype==='application/pdf'&&f.originalname.toLowerCase().endsWith('.pdf')?cb(null,true):cb(new Error('Only PDF files are accepted'))});
const validId=id=>typeof id==='string'&&/^[A-Za-z0-9_-]{4,64}$/.test(id);
const hash=b=>'0x'+crypto.createHash('sha256').update(b).digest('hex');
const parse=b=>JSON.parse(b.toString());
async function fabric(fn){
 if(!fs.existsSync(CCP))throw new Error('Fabric connection profile not found: '+CCP);
 const ccp=JSON.parse(fs.readFileSync(CCP,'utf8')),wallet=await Wallets.newFileSystemWallet(WALLET);
 if(!await wallet.get('appUser'))throw new Error('appUser missing in Fabric wallet. Configure FABRIC_WALLET_PATH.');
 const gw=new Gateway();await gw.connect(ccp,{wallet,identity:'appUser',discovery:{enabled:true,asLocalhost:true}});
 try{return await fn((await gw.getNetwork(CHANNEL)).getContract(CHAINCODE));}finally{gw.disconnect();}
}
async function all(){const b=await fabric(c=>c.evaluateTransaction('GetAllCertificates'));return parse(b);}
async function audit(user,action,id,details={}){await db.execute('INSERT INTO audit_notes(actor_user_id,action,certificate_id,details) VALUES(?,?,?,?)',[user?.id||null,action,id,JSON.stringify(details)]);}

app.get('/api/health',(req,res)=>res.json({status:'ok',application:'CertiChain API',channel:CHANNEL,chaincode:CHAINCODE}));
app.get('/api/auth/me',(req,res)=>res.json({user:req.session.user||null}));
app.post('/api/auth/register',async(req,res)=>{try{
 const name=String(req.body.fullName||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||''),studentId=String(req.body.studentId||'').trim();
 if(name.length<2||!email.includes('@')||password.length<8)return res.status(400).json({error:'Enter a name, valid email and password (8+ characters).'});
 const h=await bcrypt.hash(password,12);const [r]=await db.execute("INSERT INTO users(full_name,email,password_hash,role,student_id) VALUES(?,?,?,'student',?)",[name,email,h,studentId||null]);
 req.session.user={id:r.insertId,fullName:name,email,role:'student'};res.status(201).json({user:req.session.user});
 }catch(e){res.status(400).json({error:e.code==='ER_DUP_ENTRY'?'Email or student ID already registered.':e.message});}});
app.post('/api/auth/login',async(req,res)=>{try{
 const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');
 const [rows]=await db.execute('SELECT id,full_name,email,password_hash,role FROM users WHERE email=?',[email]);
 if(!rows.length||!await bcrypt.compare(password,rows[0].password_hash))return res.status(401).json({error:'Invalid email or password.'});
 const u=rows[0];req.session.user={id:u.id,fullName:u.full_name,email:u.email,role:u.role};res.json({user:req.session.user});
 }catch(e){res.status(500).json({error:e.message});}});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({success:true})));
app.post('/api/certificates/issue',requireAdmin,upload.single('certificate'),async(req,res)=>{let temp;
 try{
  const id=String(req.body.certificateId||'').trim(),email=String(req.body.studentEmail||'').trim().toLowerCase(),title=String(req.body.title||'').trim(),institution=String(req.body.institution||'').trim();
  if(!validId(id)||!email.includes('@')||!title||!institution)return res.status(400).json({error:'Provide a valid ID, student email, title and institution.'});
  if(!req.file||req.file.buffer.subarray(0,5).toString()!=='%PDF-')return res.status(400).json({error:'Upload a valid PDF.'});
  await fs.promises.mkdir(STORE,{recursive:true});const final=path.join(STORE,id+'.pdf');
  if(fs.existsSync(final))return res.status(409).json({error:'Stored PDF already exists for this ID.'});
  temp=path.join(STORE,id+'.'+crypto.randomUUID()+'.tmp');await fs.promises.writeFile(temp,req.file.buffer,{flag:'wx'});
  const h=hash(req.file.buffer),raw=await fabric(c=>c.submitTransaction('IssueCertificate',id,h));
  await fs.promises.rename(temp,final);temp=null;
  await db.execute('INSERT INTO certificate_metadata(certificate_id,student_email,title,institution,created_by) VALUES(?,?,?,?,?)',[id,email,title,institution,req.session.user.id]);
  await audit(req.session.user,'ISSUE',id,{studentEmail:email,title});
  res.status(201).json({certificate:parse(raw),documentHash:h,documentStored:true});
 }catch(e){if(temp)await fs.promises.unlink(temp).catch(()=>{});res.status(400).json({error:e.message});}});
app.post('/api/certificates/verify',upload.single('certificate'),async(req,res)=>{try{
 const id=String(req.body.certificateId||'').trim();if(!validId(id)||!req.file)return res.status(400).json({error:'Certificate ID and PDF are required.'});
 if(req.file.buffer.subarray(0,5).toString()!=='%PDF-')return res.status(400).json({error:'Invalid PDF signature.'});
 const h=hash(req.file.buffer),raw=await fabric(c=>c.evaluateTransaction('VerifyCertificate',id,h)),v=parse(raw);
 const status=!v.exists?'NOT_FOUND':v.revoked?'REVOKED':!v.hashMatches?'HASH_MISMATCH':'VALID';
 res.json({valid:v.valid,status,message:v.message,uploadedHash:h,record:v.certificate||null});
 }catch(e){res.status(404).json({error:e.message});}});
app.post('/api/certificates/revoke',requireAdmin,async(req,res)=>{try{
 const id=String(req.body.certificateId||'').trim();if(!validId(id))return res.status(400).json({error:'Invalid certificate ID.'});
 const raw=await fabric(c=>c.submitTransaction('RevokeCertificate',id));await audit(req.session.user,'REVOKE',id,{});
 res.json({certificate:parse(raw)});
 }catch(e){res.status(400).json({error:e.message});}});
app.get('/api/certificates',requireAdmin,async(req,res)=>{try{
 let a=await all();const search=String(req.query.search||'').toLowerCase(),status=req.query.status||'all',page=Math.max(1,+req.query.page||1),limit=Math.min(100,Math.max(1,+req.query.limit||10));
 if(!['all','active','revoked'].includes(status))return res.status(400).json({error:'Invalid status filter'});
 if(status==='active')a=a.filter(x=>!x.revoked);if(status==='revoked')a=a.filter(x=>x.revoked);
 if(search)a=a.filter(x=>x.certificateId.toLowerCase().includes(search)||String(x.issuerMspId).toLowerCase().includes(search));
 a.sort((x,y)=>new Date(y.issuedAt)-new Date(x.issuedAt));const total=a.length;
 res.json({success:true,pagination:{total,page,limit,totalPages:Math.ceil(total/limit)},certificates:a.slice((page-1)*limit,page*limit)});
 }catch(e){res.status(500).json({error:e.message});}});
app.get('/api/dashboard/stats',requireAdmin,async(req,res)=>{try{
 const a=await all(),rev=a.filter(x=>x.revoked).length;
 const [m]=await db.execute('SELECT COUNT(*) AS mappedStudents FROM certificate_metadata');
 res.json({statistics:{totalCertificates:a.length,activeCertificates:a.length-rev,revokedCertificates:rev,mappedCertificates:m[0].mappedStudents},recentCertificates:[...a].sort((x,y)=>new Date(y.issuedAt)-new Date(x.issuedAt)).slice(0,6)});
 }catch(e){res.status(500).json({error:e.message});}});
app.get('/api/certificates/:id/history',requireAdmin,async(req,res)=>{try{
 const id=req.params.id;if(!validId(id))return res.status(400).json({error:'Invalid ID'});
 const raw=await fabric(c=>c.evaluateTransaction('GetCertificateHistory',id));res.json({certificateId:id,history:parse(raw)});
 }catch(e){res.status(404).json({error:e.message});}});
app.get('/api/certificates/:id/document',requireAuth,(req,res)=>{const id=req.params.id;if(!validId(id))return res.status(400).json({error:'Invalid ID'});
 const f=path.join(STORE,id+'.pdf');if(!fs.existsSync(f))return res.status(404).json({error:'PDF not stored locally.'});res.type('application/pdf').download(f,id+'.pdf');});
app.get('/api/student/certificates',requireAuth,async(req,res)=>{if(req.session.user.role!=='student')return res.status(403).json({error:'Student account required.'});
 const [rows]=await db.execute('SELECT certificate_id AS certificateId,title,institution,created_at AS assignedAt FROM certificate_metadata WHERE student_email=? ORDER BY created_at DESC',[req.session.user.email]);
 const ledger=await all();const byId=new Map(ledger.map(x=>[x.certificateId,x]));
 res.json({certificates:rows.map(m=>({...m,ledger:byId.get(m.certificateId)||null}))});});
app.get('/api/public/verify/:id',async(req,res)=>{try{
 const id=req.params.id;if(!validId(id))return res.status(400).json({error:'Invalid ID'});
 const raw=await fabric(c=>c.evaluateTransaction('ReadCertificate',id)),r=parse(raw);
 const [m]=await db.execute('SELECT title,institution FROM certificate_metadata WHERE certificate_id=?',[id]);
 res.json({exists:true,status:r.revoked?'REVOKED':'RECORDED',valid:!r.revoked,certificateId:id,issuedAt:r.issuedAt,issuerMspId:r.issuerMspId,documentHash:r.documentHash,metadata:m[0]||null,message:r.revoked?'This certificate has been revoked.':'Ledger record found. Upload the original PDF to verify its hash.'});
 }catch(e){res.status(404).json({exists:false,status:'NOT_FOUND',valid:false,message:'Certificate record not found.'});}});
app.get('/api/public/qr/:id',async(req,res)=>{try{const id=req.params.id;if(!validId(id))return res.status(400).json({error:'Invalid ID'});
 const url=(process.env.PUBLIC_BASE_URL||`http://localhost:${PORT}`)+'/verify/?id='+encodeURIComponent(id);
 res.type('png').send(await QR.toBuffer(url,{width:300,margin:2}));
 }catch(e){res.status(500).json({error:e.message});}});
app.get('/api/admin/audit',requireAdmin,async(req,res)=>{const [rows]=await db.execute('SELECT a.id,a.action,a.certificate_id AS certificateId,a.details,a.created_at AS createdAt,u.email AS actor FROM audit_notes a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 100');res.json({events:rows});});
app.get('/api/admin/analytics',requireAdmin,async(req,res)=>{try{const a=await all();const byMonth={};for(const x of a){const k=String(x.issuedAt).slice(0,7);byMonth[k]=(byMonth[k]||0)+1;}res.json({monthly:Object.entries(byMonth).sort().map(([month,count])=>({month,count})),status:{active:a.filter(x=>!x.revoked).length,revoked:a.filter(x=>x.revoked).length}});}catch(e){res.status(500).json({error:e.message});}});
app.use((err,req,res,next)=>res.status(400).json({error:err.message||'Request failed'}));
app.listen(PORT,()=>console.log(`CertiChain running at http://localhost:${PORT}`));
