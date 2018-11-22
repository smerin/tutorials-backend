const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const { randomBytes } = require("crypto");
// const { promisify } = require("util");
// const { transport, makeANiceEmail } = require("../mail");

const Mutations = {
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] }
        }
      },
      info
    );
    // create the JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // set the jwt as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // Finallllly we return the user to the browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // 1. Check if there is a user with that email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No user found for email ${email}`);
    }
    // 2. Check if their password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid password!");
    }
    // 3. Generate the JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // 4. Set the cookie with the token
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 5. Return the user
    return user;
  },
  async signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Signed out successfully!" };
  }
  // async requestReset(parent, args, ctx, info) {
  //   // 1. Check if this is a real user
  //   const user = await ctx.db.query.user({ where: { email: args.email } });
  //   if (!user) {
  //     throw new Error(`No user found for email ${args.email}`);
  //   }
  //   // 2. Set a reset token and expiry
  //   const resetToken = (await promisify(randomBytes)(20)).toString("hex");
  //   const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
  //   const res = await ctx.db.mutation.updateUser({
  //     where: { email: args.email },
  //     data: { resetToken, resetTokenExpiry }
  //   });
  //   // 3. Email them that reset token
  //   // Consider a try / catch here to handle errors
  //   const mailRes = await transport.sendMail({
  //     from: "gsmerin@gmail.com",
  //     to: user.email,
  //     subject: "Your password reset",
  //     html: makeANiceEmail(
  //       `Your password reset token is here... \n\n<a href="${
  //         process.env.FRONTEND_URL
  //       }/reset?resetToken=${resetToken}">Click here to reset</a>`
  //     )
  //   });
  //   // 4. Return the message
  //   return { message: "Thanks!" };
  // },
  // async resetPassword(parent, args, ctx, info) {
  //   // 1. Check if the passwords match
  //   if (args.password !== args.confirmPassword) {
  //     throw new Error(`Passwords do not match`);
  //   }
  //   // 2. Check if it's a legit reset token
  //   // 3. Check if it's expired
  //   const [user] = await ctx.db.query.users({
  //     where: {
  //       resetToken: args.resetToken,
  //       resetTokenExpiry_gte: Date.now() - 3600000
  //     }
  //   });
  //   if (!user) {
  //     throw new Error(`This token is either invalid or expired`);
  //   }
  //   // 4. Hash their new password
  //   const password = await bcrypt.hash(args.password, 10);
  //   // 5. Save the new password to the user and remove old resetToken fields
  //   const updatedUser = await ctx.db.mutation.updateUser(
  //     {
  //       where: {
  //         id: user.id
  //       },
  //       data: {
  //         password,
  //         resetToken: null,
  //         resetTokenExpiry: null
  //       }
  //     },
  //     info
  //   );
  //   // 6. Generate JWT
  //   const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
  //   // 7. Set the JWT cookie
  //   ctx.response.cookie("token", token, {
  //     httpOnly: true,
  //     maxAge: 1000 * 60 * 60 * 24 * 365
  //   });
  //   // 8. Return the new user
  //   return updatedUser;
  // }
};

module.exports = Mutations;
