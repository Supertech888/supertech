const User = require("../models/register");
const registers = require("../models/register");
const jwt = require("jsonwebtoken");
const { expressjwt: exJwt } = require("express-jwt");

const bcrypt = require("bcryptjs");
const { getIP } = require("./ip");
const SECRET_KEY = process.env.SECRET_KEY

exports.logged = async (req, res) => {
  try {
    const ip = await getIP(req)

    const { username, password } = req.body;
    console.log(req.body);
    // const user =  await Users.find
    const user = await User.findOneAndUpdate({ username }, { ipAddress: ip }, { new: true });

    if (user && user.enabled) {
      //check password ระหว่าง password ปกติ และ password ที่มีการใส่รหัส
      const isMatch = await bcrypt.compare(password, user.password);


      if (!isMatch) {
        return res.status(401).json({ error: "Password Invalid" });
      }

      const payLoad = {
        user: {
          username: user.username,
          role: user.role,
          id: user._id,
        },
      };
      // // Token
      const token = jwt.sign(payLoad, SECRET_KEY, { expiresIn: "8h" });

      return res.json({ token, payLoad });
      // res.send('hello')
    } else {

      res.status(400).json({ message: "User is not Found!!" });
    }
  } catch (error) {

    res.status(400).send("SerVer is Error");
  }
};

exports.loggedLine = async (req, res) => {

  try {
    const ip = await getIP(req)

    const { userId, displayName, pictureUrl } = req.body

    let data = {
      username: displayName,
      picture: pictureUrl
    }
    let user = await User.findOneAndUpdate({ username: displayName }, { new: true });
    if (user) {
      console.log('user Updated');
    } else {
      user = new User(data);
      await user.save();
    }


    const payLoad = {
      user,

    };
    console.log(payLoad);
    const token = jwt.sign(payLoad, SECRET_KEY, { expiresIn: "8h" });
    return res.json({ token, payLoad });

    // res.send({ message: 'Login success', user });

  } catch (error) {
    console.log('error', error);

  }
};

exports.loggedFacebook = async (req, res) => {

  try {
    const { email, name, userId } = req.body;

    let data = {
      username: name,
      email: email
    };


    // ค้นหาผู้ใช้ด้วยชื่อ (username)
    let user = await User.findOne({ username: name });


    if (user) {
      // ถ้าพบผู้ใช้ ให้ทำการอัปเดตข้อมูล
      user.username = name
      user.email = email;
      await user.save();
      console.log('User Updated');
    } else {
      // ถ้าไม่พบผู้ใช้ ให้สร้างผู้ใช้ใหม่
      user = new User(data);
      await user.save();
    }

    const payLoad = {
      user
    };
    console.log("➡️  file: authController.js:114  payLoad:", payLoad)


    const token = jwt.sign(payLoad, SECRET_KEY, { expiresIn: "8h" });
    return res.json({ token, payLoad });
  } catch (error) {
    console.log('error', error);
  }
};

const fetch = require("node-fetch");
const WEB2_API = "http://localhost:5000/api/auth/external-login";
exports.externalLogin = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // ✅ ตรวจสอบ Token กับเว็บ 1 (SSO Server)
    const response = await fetch(`${process.env.WEB_API_SSO}/internal/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });

    const verifiedData = await response.json();

    if (!verifiedData || verifiedData.message) {
      return res.status(401).json({ message: "Invalid token" });
    }

    //  ดึงข้อมูลที่ต้องใช้จากเว็บ 1
    const { user } = verifiedData;
    const userId = user.sub;
    const username = `${user.username}`;

    const role = user.role;
    const displayName = user.displayName || username;
    const picture = user.picture || "";

    //  ตรวจสอบว่าผู้ใช้มีบัญชีในเว็บ 2 หรือไม่
    let existingUser = await User.findOne({ username });

    if (!existingUser) {
      //  ถ้ายังไม่มีบัญชี ให้สร้างบัญชีใหม่ในเว็บ 2
      existingUser = new User({
        _id: userId, // ใช้ `sub` ของเว็บ 1 เป็น `_id`
        username,
        role,
        enabled: true, // เปิดให้ใช้งาน
        displayName,
        picture
      });

      await existingUser.save();
    } else {

      existingUser.role = role;
      existingUser.displayName = displayName;
      existingUser.picture = picture;

      await existingUser.save();
    }

    //  สร้าง Token สำหรับเว็บ 2
    const payLoad = {
      user: {
        id: existingUser._id.toString(),
        username: existingUser.username,
        displayName: existingUser.displayName,
        email: existingUser.email,
        role: existingUser.role,
        picture: existingUser.picture
      },
    };





    const web2Token = jwt.sign(payLoad, SECRET_KEY, { expiresIn: "8h" });

    return res.json({ token: web2Token, payLoad });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};



exports.currentUser = async (req, res) => {
  console.log(`⩇⩇:⩇⩇🚨  req :`, req.user);


  try {
    const user = await User.findOne({ username: req.user.username })
      .select("-password")
      .exec();
    console.log("🚀  file: authController.js:137  user:", user)

    res.send(user);
  } catch (error) {
    res.status(400).send("SerVer is Error!!");
  }
};

