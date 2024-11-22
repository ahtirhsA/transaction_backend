const express=require('express')
const app=express()
app.use(express.json())
require('dotenv').config();

const {open}=require('sqlite')
const sqlite3=require('sqlite3')

const cors=require('cors')

app.use(cors())

const path=require('path')
const dbpath=path.join(__dirname,'transaction_model.db')

const Joi=require('joi')
const bcrypt=require('bcrypt')

const jwt=require('jsonwebtoken')

const nodemailer=require('nodemailer')

const NodeCache=require('node-cache')
const otpCache=new NodeCache({stdTTL: 300});

const transporter=nodemailer.createTransport({
    service:'gmail',
    auth:{
        user:process.env.EMAIL_USER,
        pass:process.env.EMAIL_PASS
    },
})


const PORT=3004

let db;

const initializeConnection=async ()=>{
    try{
    db=await open(
        {
            filename:dbpath,
            driver:sqlite3.Database
        }
    )

    app.listen(PORT,()=>{
        console.log(`Server is Running at http://localhost:${PORT}`);
    })
}catch(e){
    console.log(`The Error Message is ${e}`);
}
}

initializeConnection()

const validateForm=Joi.object(
    {
        username:Joi.string().required(),
        email:Joi.string().required(),
        createPassword:Joi.string().required(),
        newPassword:Joi.string().required().valid(Joi.ref('createPassword'))
    }
)

app.post('/register',async (req,res)=>{

    const {error}=validateForm.validate(req.body)

    if (error){
        return res.status(400).json({message:`Validation Error:${error.details[0].message}`})
    }

    const {username,email,createPassword,newPassword}=req.body

    const checkUser=`
       SELECT * FROM regUsers WHERE email=? 
    `

    const getUser=await db.get(checkUser,email)


    if (getUser!==undefined){
        return res.status(404).json({message:'User already exist'})
    }

    const hashedPswrd=await bcrypt.hash(newPassword,10)

    const payload={email}

    const verifiyTkn=jwt.sign(payload,process.env.IDT_SECRET)

    const verificationURL=`https://transaction-backend-qpm8.onrender.com/verify-email?token=${verifiyTkn}`


    const insrtUser=`
        INSERT INTO regUsers(username,email,password)
        VALUES(?,?,?)
    `
    await db.run(insrtUser,username,email,hashedPswrd)

    const mailOptions = {
        from:`Ashritha Trnasaction App <${process.env.EMAIL_USER}>` ,
        to: email,
        subject: 'Email Verification',
        text: `Please verify your email by clicking on the following link: ${verificationURL}`,
      };

      transporter.sendMail(mailOptions,(error, info) => {
        if (error) {
            return res.status(400).json({ message: 'Invalid email address. Please provide a valid email.' });
        }
        return res.status(200).json({ message: 'Email sent successfully! Please check your email to verify.' });
    });

})


app.get('/verify-email',async (req,res)=>{

   const {token}=req.query

   if (!token) {
    return res.status(404).json({ message: 'Invalid verification link or token not found' });
}

   jwt.verify(token,process.env.IDT_SECRET, async (error,payload)=>{
    if (error){
        return res.status(400).json({ message: 'Invalid token or expired token' });
    }
    else{
        const updQuery=`
           UPDATE regUsers SET verified= 1 WHERE email=?;
        `
        await db.run(updQuery,payload.email);
        return res.status(200).json({ message: 'Go to the application; you can log in now!' });

    }
})




})


app.post('/login',async (req,res)=>{

   const {email,password}=req.body

    const checkExistence=`
      SELECT * FROM regUsers WHERE email=?
    `

    const userExist=await db.get(checkExistence,email)

    if (userExist===undefined){
       return res.status(404).json({message:'User Not Found'})
    }

    else if (userExist!==undefined && userExist.verified===0){
        return res.status(401).json({message:'Email not verified'})
    }

    else{
        const cmpPswrd=await bcrypt.compare(password,userExist.password)

        if (cmpPswrd){
            const loginPayload={email}
            const jwtTkn=jwt.sign(loginPayload,process.env.JWT_SECRET)
            return res.status(200).json({jwtToken:jwtTkn,idn:userExist.id,name:userExist.username})  
        }
        else{
            return res.status(400).json({message:'Password did not matched'})  
        }
    }
})


app.post('/forgot-password',async (req,res)=>{

    const {email}=req.body

    if (email.trim()===''){
        return res.status(400).json({message:'email is required'})
    }

    const checkExistence=`
      SELECT * FROM regUsers WHERE email=?
    `

    const userExist=await db.get(checkExistence,email)

    if (userExist===undefined){
       return res.status(404).json({message:'User Not Found'})
    }
    else if (userExist!==undefined && userExist.verified===0){
        return res.status(401).json({message:'Email not verified'})
    }
    else{
        const generateOTP=Math.floor(100000 + Math.random() * 900000)
        otpCache.set(email,generateOTP)

        const otpMailOptions={
            from:`OTP <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Reset Password',
            text: `Your OTP is ${generateOTP}`,
        }

        transporter.sendMail(otpMailOptions,(error)=>{
            if (error){
               return res.status(400).send({ message: 'Failed to send OTP', error: error.message });
            }
            return res.status(200).send({ message: 'OTP sent successfully!' });
          })
    }

})


app.post('/verify-otp',async (req,res)=>{
    const {email,otp}=req.body

    if (!otp || !email){
        return res.status(404).json({message:'OTP  or EMAIL not found'})
    }
    else{
        if (otp==otpCache.get(email)){
            return res.status(200).json({message:'OTP verified'})

        }
        else{
            return res.status(401).json({message:'otp expired or invalid otp'})
 
        }
    }
})

app.put('/updatePassword',async (req,res)=>{
    const {email,createNewPassword,confirmNewPassword}=req.body

    if(!email){
        return res.status(404).json({message:'email is required'})

    }

    if (createNewPassword!=confirmNewPassword){
        return res.status(401).json({message:'Updated Passwords did not matched'})

    }
    else{

        const hashedCp=await bcrypt.hash(confirmNewPassword,10)
       const updPswrd=`
          UPDATE regUsers SET password=? WHERE email=?
       `;
       try{
       await db.run(updPswrd,hashedCp,email)

       return res.status(200).json({message:'Password Updated successfully'})

       }catch(e){
        return res.status(500).json({message:'Internal Server Error'})

       }
    }

})


const middlewareFunc=(req,res,next)=>{
   const authHead=req.headers['authorization']
   let jwtToken;

   if (authHead){
    jwtToken=authHead.split(' ')[1]

    if(!jwtToken){
        return res.status(404).json({message:'JWT Token missing'})
    }

    jwt.verify(jwtToken,process.env.JWT_SECRET,(err)=>{
        if(err){
            return res.status(401).json({message:'Jwt token expired or Invalid JWT Token'})
        }
        next()
    })

   }
   else{
    return res.status(400).json({message:'Authorization Headers are not defined'})
   }

}

///////////////////////////////////////////////////////////////

app.get('/',(req,res)=>{
    res.send('Hello!!');
})

app.post('/createTransaction',middlewareFunc,async (req,res)=>{
    const {amount,transaction_type,user}=req.body

    if (parseInt(amount)<=0){
        return res.status(400).json({message:'The amount should be greater than zero!!!'})
    }

    let transaction_status;

    const checkBalance=`
       SELECT 
       COALESCE(SUM(CASE
        WHEN transaction_type LIKE 'DEPOSIT'  THEN amount
        END
       ),0) AS deposit_amount,

       COALESCE(SUM(CASE
        WHEN transaction_type LIKE 'WITHDRAW'  THEN amount
        END
       ),0) AS withdraw_amount

       FROM payments WHERE user=? AND status=?
       GROUP BY user
    `;

    try {

    const resCheckBalance=await db.get(checkBalance,user,'COMPLETED');


    let availBal = 0; 


    if (resCheckBalance) {
        availBal = resCheckBalance.deposit_amount - resCheckBalance.withdraw_amount;
    }

     
    if (transaction_type=='DEPOSIT'){
           transaction_status='PENDING';
    }
    else if (transaction_type === 'WITHDRAWAL'){

        if (availBal>=amount){
            transaction_status='COMPLETED';
         }

         else{
             transaction_status='FAILED'
         }

    }

    const time_stamp=new Date().toISOString()

    const createTransaction=`
      INSERT INTO payments (amount,transaction_type,user,timestamp,status)
      VALUES(?,?,?,?,?);
    `

    const resCreateTransaction=await db.run(createTransaction,amount,transaction_type,user,time_stamp,
      transaction_status
    );

    return res.status(200).json({message:'The transaction is successful!!'});

    console.log(resCreateTransaction);
}catch(e){

    if (e.message.includes('constraint failed')) {
        return res.status(400).json({ message: `Database error: ${e.message}` });
    }
    return res.status(500).json({message:`The issue is ${e}`});
}

})


app.get('/userTrans/:id',middlewareFunc,async (req,res)=>{

    const {id}=req.params

    const retTrans=`
        SELECT * FROM payments WHERE user=?
    `;
     try{
    const resRetTrans=await db.all(retTrans,id);

    res.status(200).send({data:resRetTrans})
     }
     catch(e){
        return res.status(500).json({message:`The issue is ${e}`});   
     }
})

app.put('/updateTrans/:id',middlewareFunc,async (req,res)=>{

    const {id}=req.params
    const {status}=req.body

    const updTrans=`
      UPDATE payments SET
      status=? WHERE user=? AND status=?
    `;

    try{

    await db.run(updTrans,status,id,'PENDING')
    return res.status(200).json({message:`Updation Successful!!`});   


    }catch(e){
        return res.status(500).json({message:`The issue is ${e}`});   
     }


})

app.get('/transaction/:transId',async (req,res)=>{

    const {transId}=req.params

    const queryy=`
      SELECT * FROM payments WHERE id=?
    `
  try{

    const resQuery=await db.get(queryy,transId)

    return res.status(200).json({transactionItem:resQuery});   
  }
  catch(e){
    return res.status(500).json({message:`The issue is ${e}`});   
 }

})


app.get('/balance/:id',middlewareFunc,async (req,res)=>{

    const {id}=req.params

    const bal=`
       SELECT 
       COALESCE(SUM(CASE
        WHEN transaction_type LIKE 'DEPOSIT'  THEN amount
        END
       ),0) AS deposit_amount,

       COALESCE(SUM(CASE
        WHEN transaction_type LIKE 'WITHDRAW'  THEN amount
        END
       ),0) AS withdraw_amount

       FROM payments WHERE user=? AND status=?
       GROUP BY user
    `
   
    try{
    const ress=await db.get(bal,id,'COMPLETED')


    const balAmt=ress.deposit_amount-ress.withdraw_amount

    res.status(200).json({Amount:balAmt})

    }
    catch(e){
        return res.status(500).json({message:`The issue is ${e}`});   
     }
})


app.delete('/logout/:delId',middlewareFunc,async (req,res)=>{

    const {delId}=req.params

    const delQuery=`
        DELETE FROM regUsers WHERE id=?
    `

    try{

    await db.run(delQuery,delId)

    const delTrans=`
       DELETE FROM payments WHERE user=?
    `
    await db.run(delTrans,delId)

    return res.status(200).json({message:'User deleted successfully!!'});   


    }
    catch(e){
        return res.status(500).json({message:`The issue is ${e}`});   
     }




})