import { Router} from 'express'
import AuthController from '../../controllers/auth/auth.controller'

const authRoutes = Router()

authRoutes.post('/register',AuthController.store)
authRoutes.post('/login',AuthController.login)

export default authRoutes