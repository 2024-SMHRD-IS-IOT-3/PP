const passport = require('passport');
const KakaoStrategy = require('passport-kakao').Strategy;
const connectToOracle = require('../config/db');
const jwt = require('jsonwebtoken');

module.exports = () => {
  passport.use(new KakaoStrategy({
    clientID: process.env.KAKAO_CLIENT_ID,
    clientSecret: process.env.KAKAO_CLIENT_SECRET,
    callbackURL: process.env.KAKAO_CALLBACK_URL
  }, async (accessToken, refreshToken, profile, done) => {
    const connection = await connectToOracle();
    try {
      const { id, username } = profile;
      const email = profile._json.kakao_account.email;
      console.log('Kakao profile:', { id, email, name: username });

      let user = await connection.execute(
        'SELECT * FROM TB_USER WHERE EMAIL = :email',
        { email }
      );

      if (user.rows.length === 0) {
        await connection.execute(
          `INSERT INTO TB_USER (ID, EMAIL, NAME, PROVIDER) VALUES (:id, :email, :name, 'kakao')`,
          { id, email, name: username }
        );
        await connection.commit();
        console.log('New user created:', { id, email, name: username });
      } else {
        console.log('Existing user:', user.rows[0]);
      }

      // JWT 토큰 생성
      const token = jwt.sign({ id: user.rows[0][0] }, process.env.JWT_SECRET, {
        expiresIn: '1d'
      });

      done(null, { token });
    } catch (err) {
      done(err);
    } finally {
      await connection.close();
    }
  }));

  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((obj, done) => {
    done(null, obj);
  });
};