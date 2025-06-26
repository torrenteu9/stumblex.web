import fetch from 'node-fetch';
import session from 'express-session';
import dotenv from 'dotenv';
import { URLSearchParams } from 'url';

dotenv.config();

// Para sesiones en Vercel hay que usar un wrapper, porque Vercel no guarda estado entre llamadas.
// La forma estándar con express-session no funciona bien en serverless.
// Aquí haremos una solución simple que no use sesiones persistentes (puedes implementar JWT o cookies si quieres).

// Para mantener la estructura lo que haremos es usar cookies básicas (te recomiendo usar JWT para producción).

export default async function handler(req, res) {
  // Rutas que manejas:
  // GET /api/auth/callback?code=...
  // GET /api/auth/logout
  // GET /api/auth/user
  
  const { method, url } = req;

  // Parsear la ruta:
  if (method === 'GET' && url.startsWith('/api/auth/callback')) {
    // Extraer el código de query
    const code = new URL(req.url, `http://${req.headers.host}`).searchParams.get('code');
    if (!code) {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }

    try {
      const CLIENT_ID = process.env.CLIENT_ID;
      const CLIENT_SECRET = process.env.CLIENT_SECRET;
      const REDIRECT_URI = process.env.REDIRECT_URI;

      const data = new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        scope: 'identify guilds'
      });

      const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        body: data,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      const tokenJson = await tokenResponse.json();

      if (tokenJson.error) {
        console.log('Token error:', tokenJson);
        res.writeHead(302, { Location: '/' });
        return res.end();
      }

      const access_token = tokenJson.access_token;

      // Obtener info usuario
      const userResponse = await fetch('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      const user = await userResponse.json();

      // Obtener servidores del usuario
      const guildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      const guilds = await guildsResponse.json();

      // Aquí NO podemos usar sesión persistente, entonces puedes:
      // 1) Guardar user info en cookies JWT para mantener sesión (recomendado)
      // 2) Pasar user info en URL o frontend la pide con el access_token (menos seguro)
      //
      // Para ejemplo simple vamos a guardar un JWT en cookie (usa 'jsonwebtoken' en producción).
      //
      // Aquí lo simplifico devolviendo datos directamente para frontend manejar sesión.

      // Por simplicidad, redirigimos con token en URL (NO recomendado para producción).
      const params = new URLSearchParams({
        user: JSON.stringify(user),
        guilds: JSON.stringify(guilds)
      });
      res.writeHead(302, { Location: `/dashboard.html?${params.toString()}` });
      return res.end();

    } catch (error) {
      console.error('Callback error:', error);
      res.writeHead(302, { Location: '/' });
      return res.end();
    }
  }

  if (method === 'GET' && url.startsWith('/api/auth/logout')) {
    // Para logout en serverless solo redirigimos porque no hay sesión
    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  if (method === 'GET' && url.startsWith('/api/auth/user')) {
    // No hay sesión, devuelve falso
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ loggedIn: false }));
    return;
  }

  // Para cualquier otra petición:
  res.statusCode = 404;
  res.end('Not found');
}
