require('dotenv').config();
const express=require('express'); const helmet=require('helmet'); const cors=require('cors'); const crypto=require('crypto'); const {MongoClient}=require('mongodb');
const app=express(); const SITE=(process.env.SITE_URL||'https://agedcorps247.com').replace(/\/$/,'');
app.use(helmet()); app.use(express.json({limit:'8mb'}));
const allowedOrigins=new Set([SITE,SITE.replace('://','://www.')]);
app.use(cors({origin:(origin,cb)=>{if(!origin||allowedOrigins.has(origin))return cb(null,true);cb(new Error('Origin not allowed'));}}));
app.use((req,res,next)=>{console.log(new Date().toISOString(),req.method,req.path);next();});
const RESEND_API='https://api.resend.com/emails', FROM_EMAIL=process.env.FROM_EMAIL||'ordersupport@agedcorps247.com', FROM_NAME=process.env.FROM_NAME||'AgedCorps247 Orders';
const BRAND_LOGO=process.env.BRAND_LOGO_URL||`${SITE}/assets/images/agedcorps247-logo.png`;
function emailHeader(){return `<div style="background:#0B1C2F;padding:18px 20px;text-align:center"><img src="${BRAND_LOGO}" alt="AgedCorps247" width="560" style="display:block;width:100%;max-width:560px;height:auto;margin:0 auto"></div>`;}
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function sendEmail({to,subject,html,replyTo,attachments=[]}){if(!process.env.RESEND_API_KEY)throw new Error('RESEND_API_KEY is not configured');const p={from:`${FROM_NAME} <${FROM_EMAIL}>`,to:Array.isArray(to)?to:[to],subject,html};if(replyTo)p.reply_to=replyTo;if(attachments.length)p.attachments=attachments.map(a=>({filename:a.filename,content:a.content.toString('base64')}));const r=await fetch(RESEND_API,{method:'POST',headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(p),signal:AbortSignal.timeout(15000)});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(`Resend ${r.status}: ${d.message||JSON.stringify(d)}`);return d;}
const orderSecret=()=>process.env.ORDER_TOKEN_SECRET||'';
function token(order,email){return crypto.createHmac('sha256',orderSecret()).update(order+'|'+email.toLowerCase()).digest('hex');}
function safeTokenEqual(a,b){try{const A=Buffer.from(String(a),'hex'),B=Buffer.from(String(b),'hex');return A.length===B.length&&A.length>0&&crypto.timingSafeEqual(A,B)}catch{return false}}
function encKey(){const k=Buffer.from(process.env.DATA_ENCRYPTION_KEY||'','base64');if(k.length!==32)throw new Error('DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key');return k;}
function encrypt(value){const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',encKey(),iv);const ct=Buffer.concat([c.update(String(value),'utf8'),c.final()]);return {v:1,iv:iv.toString('base64'),tag:c.getAuthTag().toString('base64'),ct:ct.toString('base64')}}
function decrypt(o){const d=crypto.createDecipheriv('aes-256-gcm',encKey(),Buffer.from(o.iv,'base64'));d.setAuthTag(Buffer.from(o.tag,'base64'));return Buffer.concat([d.update(Buffer.from(o.ct,'base64')),d.final()]).toString('utf8')}
let dbPromise;
async function db(){if(!process.env.MONGODB_URI)throw new Error('MONGODB_URI is not configured');if(!dbPromise){const c=new MongoClient(process.env.MONGODB_URI);dbPromise=c.connect().then(()=>c.db(process.env.MONGODB_DB||'agedcorps247'));}return dbPromise;}
function admin(req,res,next){const supplied=req.get('x-admin-key')||'';const expected=process.env.ADMIN_API_KEY||'';if(!expected||supplied.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected)))return res.status(401).json({ok:false,error:'Unauthorized'});next();}
app.get('/',(req,res)=>res.json({ok:true,service:'AgedCorps247 Tradeline Orders API',version:'6-status-email'}));
app.get('/health',async(req,res)=>{let database=false;try{await (await db()).command({ping:1});database=true}catch{}res.json({ok:true,database});});

// Inventory access lead gate: require contact info and save before inventory unlocks.
app.post('/api/inventory-leads',async(req,res)=>{try{
 const name=String(req.body?.name||'').trim();
 const email=String(req.body?.email||'').trim().toLowerCase();
 const phone=String(req.body?.phone||'').trim();
 const phoneDigits=phone.replace(/\D/g,'');
 const source=String(req.body?.source||'AU Tradelines Inventory').trim().slice(0,100);
 if(name.length<2)return res.status(400).json({ok:false,error:'Please enter your full name.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({ok:false,error:'Please enter a valid email address.'});
 if(phoneDigits.length<10||phoneDigits.length>15)return res.status(400).json({ok:false,error:'Please enter a valid phone number.'});
 const D=await db();
 const now=new Date();
 const existing=await D.collection('inventoryLeads').findOne({$or:[{email},{phoneDigits}]});
 if(existing){
   await D.collection('inventoryLeads').updateOne({_id:existing._id},{$set:{name,email,phone,phoneDigits,source,lastAccessAt:now,updatedAt:now},$inc:{accessCount:1}});
 }else{
   await D.collection('inventoryLeads').insertOne({name,email,phone,phoneDigits,source,status:'new',createdAt:now,updatedAt:now,lastAccessAt:now,accessCount:1});
 }
 res.set('Cache-Control','no-store');
 res.json({ok:true,message:'Access saved.'});
}catch(e){console.error('INVENTORY_LEAD_FAILED',e.message);res.status(503).json({ok:false,error:'Unable to save your information right now. Please try again.'})}});
app.post('/api/tradeline-orders',async(req,res)=>{try{const {order,name,email,phone,sender,ref,items,total,screenshot}=req.body||{};if(!order||!name||!email||!phone||!Array.isArray(items)||!items.length||!Number.isFinite(Number(total)))return res.status(400).json({ok:false,error:'Missing required order information.'});
 const tk=token(order,email),formUrl=`${SITE}/tradeline-details.html?order=${encodeURIComponent(order)}&email=${encodeURIComponent(email)}&token=${tk}`,lines=items.map(x=>`<li>${esc(x.description)} — ${esc(x.id)} — $${Number(x.price).toLocaleString()}</li>`).join('');
 try{const D=await db();await D.collection('orders').updateOne({order},{$setOnInsert:{order,name,email:email.toLowerCase(),phone,sender:sender||'',ref:ref||'',items,total:Number(total),status:'pending_payment',createdAt:new Date()},$set:{updatedAt:new Date()}},{upsert:true});}catch(e){console.error('ORDER_DB_FAILED',order,e.message);return res.status(503).json({ok:false,error:'Secure order storage is temporarily unavailable.'});}
 let attachments=[];if(screenshot&&screenshot.data&&screenshot.name){const m=String(screenshot.data).match(/^data:(image\/(?:png|jpeg)|application\/pdf);base64,(.+)$/);if(m){const buf=Buffer.from(m[2],'base64');if(buf.length<=5*1024*1024)attachments=[{filename:String(screenshot.name).replace(/[^a-zA-Z0-9._-]/g,'_'),content:buf}]}}
 res.status(202).json({ok:true,order,formUrl,status:'pending_payment',emailDelivery:'queued'});
 setImmediate(async()=>{try{await sendEmail({to:process.env.ORDERS_EMAIL||FROM_EMAIL,replyTo:email,subject:`New Tradeline Reservation ${order} — Pending Payment`,html:`<h2>New Tradeline Reservation</h2><p><b>Order:</b> ${esc(order)}</p><p><b>Customer:</b> ${esc(name)}<br><b>Email:</b> ${esc(email)}<br><b>Phone:</b> ${esc(phone)}</p><ul>${lines}</ul><p><b>Total:</b> $${Number(total).toLocaleString()}</p><p>Status: Pending Payment</p>`,attachments});console.log('ORDER_EMAIL_SENT',order)}catch(e){console.error('ORDER_EMAIL_FAILED',order,e.message)}try{await sendEmail({to:email,subject:`AgedCorps247 Reservation ${order} — Pending Payment`,html:`<div style="font-family:Arial;max-width:640px;margin:auto">${emailHeader()}<div style="padding:24px"><h1>Reservation Received</h1><p>Hi ${esc(name)}, your order is <b>${esc(order)}</b>.</p><p><b>Status: Pending Payment</b></p><ul>${lines}</ul><p><b>Total: $${Number(total).toLocaleString()}</b></p><p>Zelle: <b>zelle@agedcorps247.com</b><br>Recipient: Good Fellas Holdings DBA AgedCorps247.com</p><p><a href="${formUrl}">COMPLETE SECURE ORDER FORM</a></p><p>Do not send SSN or DOB by email.</p></div></div>`});console.log('CUSTOMER_EMAIL_SENT',order)}catch(e){console.error('CUSTOMER_EMAIL_FAILED',order,e.message)}});
}catch(e){console.error(e);if(!res.headersSent)res.status(500).json({ok:false,error:'Unable to create reservation.'})}});
app.post('/api/tradeline-order-details',async(req,res)=>{try{const {order,email,token:tk,name,street,city,state,zip,dob,ssn,phone}=req.body||{};if(!order||!email||!tk||!name||!street||!city||!state||!zip||!dob||!ssn||!phone)return res.status(400).json({ok:false,error:'All fields are required.'});if(!safeTokenEqual(tk,token(order,email)))return res.status(403).json({ok:false,error:'Invalid or expired order link.'});
 const D=await db(),existing=await D.collection('orders').findOne({order,email:email.toLowerCase()});if(!existing)return res.status(404).json({ok:false,error:'Order not found.'});
 await D.collection('orders').updateOne({_id:existing._id},{$set:{name,phone,addressEncrypted:encrypt(JSON.stringify({street,city,state,zip})),dobEncrypted:encrypt(dob),ssnEncrypted:encrypt(ssn.replace(/\D/g,'')),status:'details_submitted',detailsSubmittedAt:new Date(),updatedAt:new Date()}});
 res.json({ok:true,order,status:'details_submitted'});setImmediate(async()=>{try{await sendEmail({to:process.env.ORDERS_EMAIL||FROM_EMAIL,subject:`Secure Order Details Submitted ${order}`,html:`<h2>Secure Order Details Submitted</h2><p><b>Order:</b> ${esc(order)}</p><p><b>Customer:</b> ${esc(name)}<br><b>Email:</b> ${esc(email)}<br><b>Phone:</b> ${esc(phone)}</p><p>SSN, DOB and address are encrypted in secure storage and are not included in this email.</p>`});}catch(e){console.error('DETAILS_EMAIL_FAILED',order,e.message)}});
}catch(e){console.error('DETAILS_SUBMIT_FAILED',e.message);res.status(500).json({ok:false,error:'Unable to securely submit details.'})}});
app.get('/api/admin/orders/:order',admin,async(req,res)=>{try{const D=await db(),o=await D.collection('orders').findOne({order:req.params.order});if(!o)return res.status(404).json({ok:false,error:'Order not found'});let sensitive=null;if(o.ssnEncrypted)sensitive={address:JSON.parse(decrypt(o.addressEncrypted)),dob:decrypt(o.dobEncrypted),ssn:decrypt(o.ssnEncrypted)};res.set('Cache-Control','no-store');res.json({ok:true,order:{order:o.order,name:o.name,email:o.email,phone:o.phone,items:o.items,total:o.total,status:o.status,createdAt:o.createdAt,detailsSubmittedAt:o.detailsSubmittedAt,...sensitive}})}catch(e){console.error('ADMIN_LOOKUP_FAILED',e.message);res.status(500).json({ok:false,error:'Unable to retrieve order'})}});
function statusEmail(o,status){
 const itemLines=(o.items||[]).map(x=>`<li>${esc(x.description||x.name||x.title||x.id||'Tradeline')} — ${esc(x.id||'')}</li>`).join('');
 const base=`<div style="font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#101828">${emailHeader()}<div style="padding:24px"><p>Order <b>${esc(o.order)}</b></p><ul>${itemLines}</ul>`;
 const end=`<p style="color:#667085;font-size:13px">For your security, SSN, date of birth and other sensitive fulfillment information are never included in status emails.</p></div></div>`;
 if(status==='payment_confirmed'){
   const tk=token(o.order,o.email), formUrl=`${SITE}/tradeline-details.html?order=${encodeURIComponent(o.order)}&email=${encodeURIComponent(o.email)}&token=${tk}`;
   const need=!o.detailsSubmittedAt;
   return {subject:`Payment Confirmed — ${o.order}`,html:base+`<h2>Payment Confirmed</h2><p>Hi ${esc(o.name)}, we have confirmed receipt of your payment. Your tradeline reservation is now moving forward.</p>${need?`<p><a href="${formUrl}" style="display:inline-block;background:#DCAE55;color:#111;text-decoration:none;padding:13px 18px;border-radius:8px;font-weight:bold">COMPLETE SECURE ORDER FORM</a></p>`:'<p>Your secure order details are already on file.</p>'}`+end};
 }
 if(status==='processing')return {subject:`Order Processing — ${o.order}`,html:base+`<h2>Your Order Is Processing</h2><p>Hi ${esc(o.name)}, your AgedCorps247 tradeline order is now being processed.</p>`+end};
 if(status==='completed')return {subject:`Order Completed — ${o.order}`,html:base+`<h2>Order Completed</h2><p>Hi ${esc(o.name)}, your AgedCorps247 tradeline order has been marked completed.</p>`+end};
 if(status==='cancelled')return {subject:`Order Cancelled — ${o.order}`,html:base+`<h2>Order Cancelled</h2><p>Hi ${esc(o.name)}, order ${esc(o.order)} has been marked cancelled. If you have questions, reply to this email.</p>`+end};
 return null;
}
app.patch('/api/admin/orders/:order/status',admin,async(req,res)=>{try{
 const allowed=['pending_payment','payment_confirmed','details_submitted','processing','completed','cancelled'],status=req.body?.status;
 if(!allowed.includes(status))return res.status(400).json({ok:false,error:'Invalid status'});
 const D=await db(),o=await D.collection('orders').findOne({order:req.params.order});if(!o)return res.status(404).json({ok:false,error:'Order not found'});
 let customerNotified=false,emailError=null;const mail=statusEmail(o,status);
 if(mail){try{await sendEmail({to:o.email,subject:mail.subject,html:mail.html,replyTo:process.env.ORDERS_EMAIL||FROM_EMAIL});customerNotified=true;console.log('STATUS_EMAIL_SENT',o.order,status)}catch(e){emailError=e.message;console.error('STATUS_EMAIL_FAILED',o.order,status,e.message)}}
 await D.collection('orders').updateOne({_id:o._id},{$set:{status,updatedAt:new Date(),lastStatusEmail:customerNotified?{status,sentAt:new Date()}:o.lastStatusEmail},$push:{statusHistory:{status,at:new Date(),customerNotified,emailError}}});
 res.json({ok:true,status,customerNotified,emailError});
}catch(e){console.error('STATUS_UPDATE_FAILED',req.params.order,e.message);res.status(500).json({ok:false,error:'Unable to update order status'})}});
app.listen(process.env.PORT||3000,()=>console.log('AC247 secure orders backend v6 running'));
