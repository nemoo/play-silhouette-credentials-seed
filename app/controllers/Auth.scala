package controllers

import models._
import utils.silhouette._
import utils.silhouette.Implicits._
import com.mohiva.play.silhouette.api.{ Silhouette, LoginInfo, SignUpEvent, LoginEvent, LogoutEvent }
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.api.util.{ Credentials, PasswordHasherRegistry, Clock }
import com.mohiva.play.silhouette.api.exceptions.ProviderException
import com.mohiva.play.silhouette.impl.providers.CredentialsProvider
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import com.mohiva.play.silhouette.impl.exceptions.{ IdentityNotFoundException, InvalidPasswordException }
import com.mohiva.play.silhouette.api.Authenticator.Implicits._
import play.api._
import play.api.mvc._
import play.api.Play.current
import play.api.data.Form
import play.api.data.Forms._
import play.api.data.validation.Constraints._
import play.api.i18n.{ MessagesApi, Messages }
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits._
import scala.concurrent.duration._
import net.ceedubs.ficus.Ficus._
import javax.inject.{ Inject, Singleton }
import views.html.{ auth => viewsAuth }

@Singleton
class Auth @Inject() (
    val silhouette: Silhouette[MyEnv],
    val messagesApi: MessagesApi,
    userService: UserService,
    authInfoRepository: AuthInfoRepository,
    credentialsProvider: CredentialsProvider,
    passwordHasherRegistry: PasswordHasherRegistry,
    conf: Configuration,
    clock: Clock
) extends AuthController {

  // UTILITIES

  val passwordValidation = nonEmptyText(minLength = 6)
  def notFoundDefault(implicit request: RequestHeader) = Future.successful(NotFound(views.html.errors.notFound(request)))

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // SIGN IN

  val signInForm = Form(tuple(
    "identifier" -> email,
    "password" -> nonEmptyText,
    "rememberMe" -> boolean
  ))

  /**
   * Starts the sign in mechanism. It shows the login form.
   */
  def signIn = UserAwareAction { implicit request =>
    request.identity match {
      case Some(user) => Redirect(routes.Application.index)
      case None => Ok(viewsAuth.signIn(signInForm))
    }
  }

  /**
   * Authenticates the user based on his email and password
   */
  def authenticate = UnsecuredAction.async { implicit request =>
    signInForm.bindFromRequest.fold(
      formWithErrors => Future.successful(BadRequest(viewsAuth.signIn(formWithErrors))),
      formData => {
        val (identifier, password, rememberMe) = formData
        val entryUri = request.session.get("ENTRY_URI")
        val targetUri: String = entryUri.getOrElse(routes.Application.index.toString)
        credentialsProvider.authenticate(Credentials(identifier, password)).flatMap { loginInfo =>
          userService.retrieve(loginInfo).flatMap {
            case Some(user) => for {
              authenticator <- env.authenticatorService.create(loginInfo).map(authenticatorWithRememberMe(_, rememberMe))
              cookie <- env.authenticatorService.init(authenticator)
              result <- env.authenticatorService.embed(cookie, Redirect(targetUri).withSession(request.session - "ENTRY_URI"))
            } yield {
              env.eventBus.publish(LoginEvent(user, request))
              result
            }
            case None => Future.failed(new IdentityNotFoundException("Couldn't find user"))
          }
        }.recover {
          case e: ProviderException => Redirect(routes.Auth.signIn).flashing("error" -> Messages("auth.credentials.incorrect"))
        }
      }
    )
  }

  private def authenticatorWithRememberMe(authenticator: CookieAuthenticator, rememberMe: Boolean) = {
    if (rememberMe) {
      authenticator.copy(
        expirationDateTime = clock.now + rememberMeParams._1,
        idleTimeout = rememberMeParams._2,
        cookieMaxAge = rememberMeParams._3
      )
    } else
      authenticator
  }
  private lazy val rememberMeParams: (FiniteDuration, Option[FiniteDuration], Option[FiniteDuration]) = {
    val cfg = conf.getConfig("silhouette.authenticator.rememberMe").get.underlying
    (
      cfg.as[FiniteDuration]("authenticatorExpiry"),
      cfg.getAs[FiniteDuration]("authenticatorIdleTimeout"),
      cfg.getAs[FiniteDuration]("cookieMaxAge")
    )
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // SIGN OUT

  /**
   * Signs out the user
   */
  def signOut = SecuredAction.async { implicit request =>
    env.eventBus.publish(LogoutEvent(request.identity, request))
    env.authenticatorService.discard(request.authenticator, Redirect(routes.Application.index))
  }

}