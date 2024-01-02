import jwt from 'jsonwebtoken'
import type { Request } from 'express'
import { getCacheConfig } from '../storage/config'
import { createUser, getUser, getUserById } from '../storage/mongo'
import { Status, UserRole } from '../storage/model'

const auth = async (req, res, next) => {
  const config = await getCacheConfig()

  if (config.siteConfig.loginBySsoProxy) {
    try {
      const username = req.header('X-Email')
      const user = await getUser(username)
      req.headers.userId = user._id
      next()
    }
    catch (error) {
      res.send({ status: 'Unauthorized', message: error.message ?? 'Please config sso proxy (usually is nginx) add proxy header X-Email.', data: null })
    }
    return
  }

  if (config.siteConfig.loginEnabled) {
    try {
      const token = req.header('Authorization').replace('Bearer ', '')
      const info = jwt.verify(token, config.siteConfig.loginSalt.trim())
      req.headers.userId = info.userId
      const user = await getUserById(info.userId)
      if (user == null || user.status !== Status.Normal)
        throw new Error('用户不存在 | User does not exist.')
      else
        next()
    }
    catch (error) {
      res.send({ status: 'Unauthorized', message: error.message ?? 'Please authenticate.', data: null })
    }
  }
  else {
    // fake userid
    req.headers.userId = '6406d8c50aedd633885fa16f'
    next()
  }
}

async function getUserId(req: Request): Promise<string | undefined> {
  try {
    const config = await getCacheConfig()

    if (config.siteConfig.loginBySsoProxy) {
      const username = req.header('X-Email')
      let user = await getUser(username)
      if (user == null) {
        const isRoot = username.toLowerCase() === process.env.ROOT_USER
        user = await createUser(username, '', isRoot ? [UserRole.Admin] : [UserRole.User], Status.Normal, 'Created by SSO proxy.')
      }
      return user._id.toString()
    }

    const token = req.header('Authorization').replace('Bearer ', '')
    const info = jwt.verify(token, config.siteConfig.loginSalt.trim())
    return info.userId
  }
  catch (error) {

  }
  return null
}

export { auth, getUserId }
