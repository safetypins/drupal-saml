<?php

namespace Drupal\onelogin_saml\Controller;

use Drupal\Core\Controller\ControllerBase;

class SamlProcessor extends ControllerBase {
  public function onelogin_saml_sso() {
    $user = \Drupal::currentUser();
  }
  
  public function onelogin_saml_acs() {
    $user = \Drupal::currentUser();

    // If a user initiates a login while they are already logged in, send
    // them to their profile.
    if (\Drupal::currentUser()->isAnonymous()) {
      return $this->redirect('user.page');
    } else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
      $auth = initialize_saml();

      $auth->processResponse();

      $errors = $auth->getErrors();
      if (!empty($errors)) {
        drupal_set_message("There was at least one error processing the SAML Response".implode("<br>", $errors), 'error', FALSE);
      } else {
        onelogin_saml_auth($auth);
      }
    }
    else {
      drupal_set_message("No SAML Response found.", 'error', FALSE);
    }

    drupal_goto('');
  }
  
  public function onelogin_saml_sls() {
    $user = \Drupal::currentUser();
  }
  
  public function onelogin_saml_metadata() {
    $user = \Drupal::currentUser();
  }
  
  protected function initialize_saml() {
    $config = \Drupal::config('onelogin_saml.settings');
    require_once '_toolkit_loader.php';

    try {
      $auth = new Onelogin_Saml2_Auth($settings);
    } catch (Exception $e) {
      drupal_set_message("The Onelogin SSO/SAML plugin is not correctly configured:".'<br>'.$e->getMessage(), 'error', FALSE);
      drupal_goto();
    }

    return $auth;
  }
}