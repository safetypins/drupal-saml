<?php

namespace Drupal\onelogin_saml\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Utility\Error;
use Drupal\Component\Utility\UrlHelper;

/**
 * Configure SAML Authentication settings for this site.
 */
class OneLoginSamlSettingsForm extends ConfigFormBase {
  /** 
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'onelogin_saml_settings';
  }

  /** 
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'onelogin_saml.settings',
    ];
  }

  /** 
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('onelogin_saml.settings');

    $form['provider'] = [
      '#type' => 'details',
      '#title' => $this->t('Identity Provider Settings'),
      '#tree' => TRUE,
      '#open' => TRUE,
      '#description' => $this->t('Add information about your Identity Provider.'),
    ];

    $form['provider']['idp_entity_id'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('IdP Entity ID'),
      '#required' => TRUE,
      '#default_value' => $config->get('provider')['idp_entity_id'],
      '#description' => $this->t('Identifier of the IdP entity. ("Issuer URL")'),
    );

    $form['provider']['sso_service_url'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Single Sign On Service Url'),
      '#required' => TRUE,
      '#default_value' => $config->get('provider')['sso_service_url'],
      '#description' => $this->t('URL target of the IdP where the SP will send the Authentication Request. If your IdP has multiple URL targets, the one that uses the HTTP Redirect Binding should be used here. ("SAML 2.0 Endpoint (HTTP)")'),
    );
    
    $form['provider']['single_logout'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Single Log Out'),
      '#default_value' => $config->get('provider')['single_logout'],
      '#description' => $this->t('Enable SAML Single Log Out. SLO is complex functionality. The most common SLO implementation is based on front-channel (redirections). Sometimes if the SLO workflow fails, a user can be blocked in an unhandled view. Unless you have a strong grasp of SLO it is recommended that you leave it disabled. If enabled, enter the IdP&rsquo;s SLO target URL below.'),
    );

    $form['provider']['single_logout_url'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Single Log Out Service Url'),
      '#default_value' => $config->get('provider')['single_logout_url'],
      '#description' => $this->t('URL target for the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")'),
    );

    $form['provider']['logout_redirect'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Logout Redirect'),
      '#default_value' => $config->get('provider')['logout_redirect'],
      '#description' => $this->t('If Single Log Out is not used, you can choose to redirect a SAML user after they are logged out of Drupal. Some use this to redirect to an IdP logout page, a Central Authentication Service (CAS) logout page, or a custom page warning the user to close their browser to end their SSO session. This only affects users who have logged in via SAML.'),
    );

    $form['provider']['x_509_certificate'] = array(
      '#type' => 'textarea',
      '#title' => $this->t('X.509 Certificate'),
      '#required' => TRUE,
      '#default_value' => $config->get('provider')['x_509_certificate'],
      '#description' => $this->t('Public x509 certificate of the IdP. The full certificate (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----) is required. ("X.509 certificate")'),
    );

    $form['options'] = [
      '#type' => 'details',
      '#title' => $this->t('Options'),
      '#tree' => TRUE,
      '#open' => TRUE,
      '#description' => $this->t('Configure the behavior of this module.'),
    ];

    $form['options']['create_user'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Create account if one does not exist'),
      '#default_value' => $config->get('options')['create_user'],
      '#description' => $this->t('Auto-provisioning. If user not exists, this module will create a new user with the data provided by the IdP. Review the Mapping section.'),
    );

    $form['options']['username_from_email'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Get username from email address'),
      '#default_value' => $config->get('options')['username_from_email'],
      '#description' => $this->t('Use everything in front of the @ in the email address as the username. This may be useful if you are only sending an email address in your SAML response, but you want to auto-provision accounts which requires a username and email address.'),
    );

    $form['options']['sync_roles'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Sync roles'),
      '#default_value' => $config->get('options')['sync_roles'],
      '#description' => $this->t('Auto-sync. The role of the Drupal user account will be synchronized with the data provided by the IdP. Review the Mapping section.'),
    );

    $form['options']['saml_link'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('SAML link'),
      '#default_value' => $config->get('options')['saml_link'],
      '#description' => $this->t('Show a SAML link to execute a SP-initiated SSO on the login page.'),
    );

    $form['options']['account_match'] = array(
      '#type' => 'select',
      '#title' => $this->t('Match Drupal account by'),
      '#required' => TRUE,
      '#default_value' => $config->get('options')['account_match'],
      '#options' => array(
        'username' => 'username',
        'email' => 'email',
      ),
      '#description' => $this->t('Select what field will be used in order to find the user account. If you select the "email" fieldname remember to prevent that the user is able to change his mail in his profile.'),
    );

    $form['attribute_mapping'] = [
      '#type' => 'details',
      '#title' => $this->t('Attribute Mapping'),
      '#tree' => TRUE,
      '#open' => TRUE,
      '#description' => $this->t('Sometimes the names of the attributes sent by the IdP not match the names used by Drupal for the user accounts. In this section we can set the mapping between IdP fields and Drupal fields. Notice that this mapping could be also set at Onelogin&rsquo;s IdP.'),
    ];

    $form['attribute_mapping']['username'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Username'),
      '#required' => TRUE,
      '#default_value' => $config->get('attribute_mapping')['username'],
      '#description' => $this->t('Be sure that usernames at the IdP don&rsquo;t contain punctuation (periods, hyphens, apostrophes, and underscores are allowed)'),
    );

    $form['attribute_mapping']['email'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Email'),
      '#required' => TRUE,
      '#default_value' => $config->get('attribute_mapping')['email'],
    );

    $form['attribute_mapping']['role'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Role'),
      '#default_value' => $config->get('attribute_mapping')['role'],
    );

    $form['attribute_mapping']['administrator'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Administrator'),
      '#default_value' => $config->get('attribute_mapping')['administrator'],
      '#description' => $this->t('The IdP can use it&rsquo;s own roles. Set in this section the mapping between IdP and Drupal roles. Accepts multiple valued comma separated. Example: admin,owner,superuser.'),
    );

    $form['ux'] = [
      '#type' => 'details',
      '#title' => $this->t('User Experience'),
      '#tree' => TRUE,
      '#description' => $this->t('When implementing SSO, users may become confused with menus and links that allow them to manage a local Drupal password or request a new account. These options allow you to customize the experience for SAML users with the hopes of avoiding some of the confusion.'),
    ];
    
    $form['ux']['disable_password_field'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Disable current password field on user profiles'),
      '#default_value' => $config->get('ux')['disable_password_field'],
      '#description' => $this->t('You may wish to limit a user from creating and managing a Drupal password. The user profile form includes a current password field that is required as validation in order to update certain user profile fields (such as email address). If the user does not have a Drupal password, this will get in the way. This option disables the field for users who have logged in via SAML. Users with the Administrator role are exempt.'),
    );

    $form['ux']['disable_password_tab'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Disable user password tab and related page'),
      '#default_value' => $config->get('ux')['disable_password_tab'],
      '#description' => $this->t('You may wish to limit a user from creating and managing a Drupal password. This option disables the menu tabs associated with the user password page. This option disables the password page for users who have logged in via SAML. Users with the Administrator role are exempt.'),
    );

    $form['ux']['custom_new_account_link'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Custom Create new account link'),
      '#default_value' => $config->get('ux')['custom_new_account_link'],
      '#description' => $this->t('Depending on your Drupal implementation, you may allow requests for new accounts from the Drupal login page. Rather than using Drupal&rsquo;s request form, you can direct users to your company&rsquo;s account request form.'),
    );

    $form['ux']['custom_new_password_link'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Custom Request new password link'),
      '#default_value' => $config->get('ux')['custom_new_password_link'],
      '#description' => $this->t('If you have enabled the Request new password link in Drupal, a SSO user could click the link and go through the process believing that their SSO account password is being changed. In reality this would only change their local Drupal password. To avoid this confusion you can direct users to your company&rsquo;s password management system.'),
    );

    $form['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced Settings'),
      '#tree' => TRUE,
    ];

    $form['advanced']['debug'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Debug Mode'),
      '#default_value' => $config->get('advanced')['debug'],
      '#description' => $this->t('Enable it when you are debugging the SAML workflow. Errors and Warnigs will be showed.'),
    );

    $form['advanced']['strict'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Strict Mode'),
      '#default_value' => $config->get('advanced')['strict'],
      '#description' => $this->t('If Strict mode is Enabled, then Drupal will reject unsigned or unencrypted messages if it expects them signed or encrypted. Also it will reject the messages if they do not strictly follow the SAML standard: Destination, NameId, Conditions ... are validated too.'),
    );

    $form['advanced']['sp_entity_id'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Service Provider Entity Id'),
      '#default_value' => $config->get('advanced')['sp_entity_id'],
      '#description' => $this->t('Set the Entity ID for the Service Provider. If not provided, "php-saml" will be used.'),
    );

    $form['advanced']['name_id_format'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('NameID Format'),
      '#default_value' => $config->get('advanced')['name_id_format'],
      '#description' => $this->t('Set the NameId format that the Service Provider and Identity Provider will use. If not provided, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" will be used.'),
    );

    $form['signing_encryption'] = [
      '#type' => 'details',
      '#title' => $this->t('SIGNING/ENCRYPTION SETTINGS'),
      '#tree' => TRUE,
      '#description' => $this->t('<p>If signing/encryption is enabled, then a x509 cert and private key for the SP must be provided. There are two ways to supply the certificate and key:</p><ol><li>Store them as files named sp.key and sp.crt in the "certs" folder of this Drupal module (be sure that the folder is protected and not exposed to the Internet).</li><li>Paste the certificate and key text in the corresponding textareas (review any database security issues as to limit the exposure of the key).</li></ol><p><strong>Please be aware:</strong> if you encrypt the entire SAML Assertion, this module <strong>will not be able to decrypt attributes</strong>. Much of the functionality of this module depends on attributes (auto-provisioning, role sync, etc.). If you can live without encrypting the entire SAML Assertion, your attributes will work and additional security can be implemented by encrypting the NameId and enforcing signed requests/responses.</p>'),
    ];

    $form['signing_encryption']['encrypt_name_id'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Encrypt nameID'),
      '#default_value' => $config->get('signing_encryption')['encrypt_name_id'],
    );

    $form['signing_encryption']['authentication_request'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Sign AuthnRequest'),
      '#default_value' => $config->get('signing_encryption')['authentication_request'],
    );

    $form['signing_encryption']['logout_request'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Sign LogoutRequest'),
      '#default_value' => $config->get('signing_encryption')['logout_request'],
    );

    $form['signing_encryption']['logout_response'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Sign LogoutResponse'),
      '#default_value' => $config->get('signing_encryption')['logout_response'],
    );

    $form['signing_encryption']['reject_unsigned_messages'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Reject Unsigned Messages'),
      '#default_value' => $config->get('signing_encryption')['reject_unsigned_messages'],
    );

    $form['signing_encryption']['reject_unsigned_assertions'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Reject unsigned saml:Assertion received'),
      '#default_value' => $config->get('signing_encryption')['reject_unsigned_assertions'],
    );

    $form['signing_encryption']['reject_unencrypted_assertions'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Reject Unencrypted Assertions'),
      '#default_value' => $config->get('signing_encryption')['reject_unencrypted_assertions'],
    );

    $form['signing_encryption']['sp_x_509_certificate'] = array(
      '#type' => 'textarea',
      '#title' => $this->t(''),
      '#default_value' => $config->get('signing_encryption')['sp_x_509_certificate'],
      '#description' => $this->t('Public x509 certificate of the SP. The full certificate (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----) is required. Leave this field empty if you have added sp.crt to the certs folder of this module.'),
    );

    $form['signing_encryption']['sp_private_key'] = array(
      '#type' => 'textarea',
      '#title' => $this->t('Service Provider Private Key'),
      '#default_value' => $config->get('signing_encryption')['sp_private_key'],
      '#description' => $this->t('Private Key of the SP. The full certificate (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----) is required. Leave this field empty if have added sp.key to the certs folder of this module.'),
    );

    return parent::buildForm($form, $form_state);
  }

  /** 
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $config = $this->config('onelogin_saml.settings');

    // Retrieve the configuration
    $config->set('provider', $form_state->getValue('provider'));
    $config->set('options', $form_state->getValue('options'));
    $config->set('attribute_mapping', $form_state->getValue('attribute_mapping'));
    $config->set('ux', $form_state->getValue('ux'));
    $config->set('advanced', $form_state->getValue('advanced'));
    $config->set('signing_encryption', $form_state->getValue('signing_encryption'));
    $config->save();

    parent::submitForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if (!UrlHelper::isValid($form_state->getValue('provider')['idp_entity_id'], true)) {
      $form_state->setErrorByName('provider][idp_entity_id', $this->t('Must be a valid absolute URL.'));
    }
    if (!UrlHelper::isValid($form_state->getValue('provider')['sso_service_url'], true)) {
      $form_state->setErrorByName('provider][sso_service_url', $this->t('Must be a valid absolute URL.'));
    }
    if ($form_state->getValue('provider')['single_logout_url'] != '') {
      if (!UrlHelper::isValid($form_state->getValue('provider')['single_logout_url'], true)) {
        $form_state->setErrorByName('provider][single_logout_url', $this->t('Must be a valid absolute URL.'));
      }
    }
    if ($form_state->getValue('provider')['logout_redirect'] != '') {
      if (!UrlHelper::isValid($form_state->getValue('provider')['logout_redirect'], true)) {
        $form_state->setErrorByName('provider][logout_redirect', $this->t('Must be a valid absolute URL.'));
      }
    }
    if ($form_state->getValue('ux')['custom_new_account_link'] != '') {
      if (!UrlHelper::isValid($form_state->getValue('ux')['custom_new_account_link'], true)) {
        $form_state->setErrorByName('ux][custom_new_account_link', $this->t('Must be a valid absolute URL.'));
        $form['ux']['#open'] = true;
      }
    }
    if ($form_state->getValue('ux')['custom_new_password_link'] != '') {
      if (!UrlHelper::isValid($form_state->getValue('ux')['custom_new_password_link'], true)) {
        $form_state->setErrorByName('ux][custom_new_password_link', $this->t('Must be a valid absolute URL.'));
        $form['ux']['#open'] = true;
      }
    }
    // ksm($form['ux']['#open']);
  }
}
