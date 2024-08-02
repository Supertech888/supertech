const registers = require("../models/register");
const bcrypt = require("bcryptjs");

exports.register = (req, res) => {
  const { username, password } = req.body;

  switch (true) {
    case !username:
      res.status(400).json({ error: "กรุณากรอกข้อมูล username" });
      break;
    case !password:
      res.status(400).json({ error: "กรุณากรอกข้อมูล password" });
      break;
  }
  //การบันทึกข้อมูล จะใช้คำสั่ง create และตามด่วย document
  registers.create({ username, password }, (err, register) => {
    if (err) {
      res.status(400).json({ error: err });
    }
    res.json(register);
  });
  //   res.json({
  //       data: {username , password , confirmpass}
  //   })
};

exports.register2 = async (req, res) => {


  try {
    const { username, password } = req.body;
    let user = await registers.findOne({ username });

    if (user) {
      return res.status(400).send("User Already exists");
    }
    const salt = await bcrypt.genSalt(10);

    user = new registers({
      username,
      password,
    });
    
    
    user.password = await bcrypt.hash(password, salt);


    // 
    await user.save();
    res.send({ message: 'register success', user });
  } catch (error) {
    res.status(500).send('server is error!!!!')
  }
};




exports.removeUser = async (req, res) => {
  try {
    console.log('มีอะไรไหม', req.body);
    const id = req.params.id;

    // { new: true } คือ การให้แสดงค่าใหม่
    await registers.findOneAndRemove({ _id: id }).exec();
    res.json({ message: "ทำการลบข้อมูลสำเร็จ" });
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};


