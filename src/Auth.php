<?php

namespace Auth;

use Auth\Session;

class Auth
{
   private static IdentityInterface $user;

   private static array $apiTokens = [];

public static function generateApiToken(IdentityInterface $user): string
{
    $token = bin2hex(random_bytes(16));
    self::$apiTokens[$token] = $user->getId();
    return $token;
}

public static function userFromToken(string $token): ?IdentityInterface
{
    $userId = self::$apiTokens[$token] ?? null;
    if (!$userId) return null;
    return self::$user->findIdentity($userId);
}

   public static function init(IdentityInterface $user): void
   {
       self::$user = $user;
       if (self::user()) {
           self::login(self::user());
       }
   }

   public static function login(IdentityInterface $user): void
   {
       self::$user = $user;
       
       Session::set('id', self::$user->getId());
   }

   public static function attempt(array $credentials): bool
   {
        
        if ($user = self::$user->attemptIdentity($credentials)) {
            self::login($user);
            return true;
        }
        return false;
   }

   public static function user()
   {
       $id = Session::get('id') ?? 0;
       return self::$user->findIdentity($id);
   }


   public static function check(): bool
   {
       if (self::user()) {
           return true;
       }
       return false;
   }

   public static function generateCSRF(): string
{
   $token = md5(time());
   Session::set('csrf_token', $token);
   return $token;
}


   //Выход текущего пользователя
   public static function logout(): bool
   {
       Session::clear('id');
       return true;
   }

}