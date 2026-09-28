require('dotenv').config();
const express=require('express'); const helmet=require('helmet'); const cors=require('cors'); const nodemailer=require('nodemailer'); const crypto=require('crypto');
const app=express(); const SITE=(process.env.SITE_URL||'https://agedcorps247.com').replace(/\/$/,'');
app.use(helmet());
app.use(express.json({limit:'8mb'}));
const allowedOrigins=new Set([SITE, SITE.replace('://','://www.')]);
app.use(cors({origin:(origin,cb)=>{if(!origin||allowedOrigins.has(origin)) return cb(null,true); cb(new Error('Origin not allowed'));}}));
app.use((req,res,next)=>{console.log(new Date().toISOString(),req.method,req.path);next();});
const tx=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||465),secure:String(process.env.SMTP_SECURE)!=='false',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS},connectionTimeout:12000,greetingTimeout:12000,socketTimeout:20000});
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const secret=()=>process.env.ORDER_TOKEN_SECRET||'change-me';
function token(order,email){return crypto.createHmac('sha256',secret()).update(order+'|'+email.toLowerCase()).digest('hex');}
app.get('/',(req,res)=>res.json({ok:true,service:'AgedCorps247 Tradeline Orders API'}));
app.get('/health',(req,res)=>res.json({ok:true}));
app.post('/api/tradeline-orders',async(req,res)=>{try{const {order,name,email,phone,sender,ref,items,total,screenshot}=req.body||{}; if(!order||!name||!email||!phone||!Array.isArray(items)||!items.length||!Number.isFinite(Number(total))) return res.status(400).json({ok:false,error:'Missing required order information.'});
const tk=token(order,email); const formUrl=`${SITE}/tradeline-details.html?order=${encodeURIComponent(order)}&email=${encodeURIComponent(email)}&token=${tk}`;
const lines=items.map(x=>`<li>${esc(x.description)} — ${esc(x.id)} — $${Number(x.price).toLocaleString()}</li>`).join('');
let attachments=[];
if(screenshot&&screenshot.data&&screenshot.name){
  const m=String(screenshot.data).match(/^data:(image\/(?:png|jpeg)|application\/pdf);base64,(.+)$/);
  if(m){const buf=Buffer.from(m[2],'base64'); if(buf.length<=5*1024*1024) attachments=[{filename:String(screenshot.name).replace(/[^a-zA-Z0-9._-]/g,'_'),content:buf,contentType:m[1]}];}
}
await tx.sendMail({from:`${process.env.FROM_NAME||'AgedCorps247 Orders'} <${process.env.SMTP_USER}>`,to:process.env.ORDERS_EMAIL||'ordersupport@agedcorps247.com',replyTo:email,subject:`New Tradeline Reservation ${order} — Pending Payment`,html:`<h2>New Tradeline Reservation</h2><p><b>Order:</b> ${esc(order)}</p><p><b>Customer:</b> ${esc(name)}<br><b>Email:</b> ${esc(email)}<br><b>Phone:</b> ${esc(phone)}<br><b>Zelle sender:</b> ${esc(sender||'Not provided')}<br><b>Reference:</b> ${esc(ref||'Not provided')}</p><ul>${lines}</ul><p><b>Total:</b> $${Number(total).toLocaleString()}</p><p>Status: Pending Payment</p>${attachments.length?'<p><b>Zelle screenshot attached.</b></p>':'<p>No Zelle screenshot uploaded. Customer may email it separately using the order number.</p>'}`,attachments});
await tx.sendMail({from:`${process.env.FROM_NAME||'AgedCorps247 Orders'} <${process.env.SMTP_USER}>`,to:email,subject:`AgedCorps247 Reservation ${order} — Pending Payment`,html:`<div style="font-family:Arial;max-width:640px;margin:auto"><h1 style="color:#0B1C2F">Reservation Received</h1><p>Hi ${esc(name)}, we received your tradeline reservation <b>${esc(order)}</b>.</p><p><b>Order Status: Pending Payment</b></p><ul>${lines}</ul><p><b>Total: $${Number(total).toLocaleString()}</b></p><p>Send the exact total by Zelle to <b>zelle@agedcorps247.com</b><br>Recipient: <b>Good Fellas Holdings DBA AgedCorps247.com</b>.</p><p>Your order will begin processing once your payment has been received and confirmed. Please complete your order form so the required fulfillment information is on file.</p><p><a href="${formUrl}" style="background:#D9AC5C;color:#0B1C2F;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:bold">COMPLETE ORDER FORM</a></p><p style="font-size:12px;color:#666">Do not send your SSN or DOB by email.</p></div>`});
res.json({ok:true,order,formUrl});}catch(e){console.error(e);res.status(500).json({ok:false,error:'Unable to submit order right now.'})}});
// Sensitive fulfillment endpoint: does not email SSN/DOB. Replace encrypted persistence with your approved secure datastore before production.
app.post('/api/tradeline-order-details',async(req,res)=>{try{const {order,email,token:tk,name,address,dob,ssn,phone}=req.body||{}; if(!order||!email||!tk||!name||!address||!dob||!ssn||!phone) return res.status(400).json({ok:false,error:'All fields are required.'}); const good=crypto.timingSafeEqual(Buffer.from(tk),Buffer.from(token(order,email))); if(!good)return res.status(403).json({ok:false,error:'Invalid order link.'});
// Intentionally do not log, email, or write SSN/DOB to disk in this starter backend.
await tx.sendMail({from:`${process.env.FROM_NAME||'AgedCorps247 Orders'} <${process.env.SMTP_USER}>`,to:process.env.ORDERS_EMAIL||'ordersupport@agedcorps247.com',subject:`Order Form Submitted ${order}`,html:`<h2>Order Form Submitted</h2><p><b>Order:</b> ${esc(order)}</p><p><b>Customer:</b> ${esc(name)}<br><b>Email:</b> ${esc(email)}<br><b>Phone:</b> ${esc(phone)}</p><p>Sensitive identity fields were submitted through the secure form and were not included in this email.</p><p><b>Important:</b> This starter backend does not persist SSN/DOB. Connect an encrypted restricted-access datastore before using this endpoint for live fulfillment.</p>`}); res.json({ok:true});}catch(e){console.error(e);res.status(500).json({ok:false,error:'Unable to submit details.'})}});
app.listen(process.env.PORT||3000,()=>console.log('AC247 orders backend running'));
