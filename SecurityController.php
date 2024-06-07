<?php

namespace App\Controller;

use App\Modules\AppStatistiques;
use App\Modules\AppEmails;
use App\Modules\AppSms;

use App\Entity\SecurUser;
use App\Repository\SecurUserRepository;
use App\Entity\SecurIpbann;
use App\Repository\SecurIpbannRepository;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Doctrine\ORM\EntityManagerInterface;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\TelType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\CallbackTransformer;




class SecurityController extends AbstractController
{

    /** Variables globales ************************************************************ */
    public $raccActivation = "/activation/";
    public $raccInvitation = "/invitation/";
    public $limiteEssai = 4;


    /** Constructeur ****************************************************************** */
    public function __construct(
        AppStatistiques $stats,
        AppEmails $sendMailx,
        AppSms $sendSmsx,
        SecurUserRepository $userRepo,
        SecurIpbannRepository $ipbannRepo,
        UserPasswordHasherInterface $passwordEncoder, 
        CsrfTokenManagerInterface $csrfTokenManager,
        EntityManagerInterface $em
    )
    {
        $this->stats = $stats;
        $this->sendMailx = $sendMailx;
        $this->sendSmsx = $sendSmsx;
        $this->userRepo = $userRepo;
        $this->ipbannRepo = $ipbannRepo;
        $this->passwordEncoder = $passwordEncoder;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->em = $em;
    }





    /** Pages  ************************************************************************* */

    #[Route(path: '/login', name: 'secur_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // 1. Test si il existe au moins un admin
        $firstAdminRoute = $this->ifNoAdmin();
        if ($firstAdminRoute) {
            return $this->redirectToRoute($firstAdminRoute);
        }

        // 2. enregistre la visite de la page
        $this->stats->enregistreStat("Sécurité Login");

        // 3. Récupérer les erreurs de connexion
        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/pages/login.html.twig', [
            'controller_name' => 'secur_login',
            'last_username' => $lastUsername, 
            'error' => $error
        ]);

    }

    #[Route(path: '/logout', name: 'secur_logout')]
    public function logout(): void
    {
        // 2. enregistre la visite de la page
        $this->stats->enregistreStat("Sécurité Logout");

        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }


    #[Route(path: '/firstAdmin', name: 'secur_firstAdmin')]
    public function secur_firstAdmin(Request $request, UserPasswordHasherInterface $passwordHasher): Response
    {
        // 1. Test si l'utilisateur est banni
        $bannedRoute = $this->ifBanniUser();
        if ($bannedRoute) {
            $this->stats->enregistreStat("Page secur_firstAdmin redirection banni");
            return $this->redirectToRoute($bannedRoute);
        }

        // 2. Test si il existe au moins un admin actif
        $firstAdminRoute = $this->ifNoAdmin();
        if (!$firstAdminRoute) {
            $this->stats->enregistreStat("secur_firstAdmin redirection front_index");
            return $this->redirectToRoute('front_index');
        }

        // 3. Enregistre la visite de la page
        $this->stats->enregistreStat("Sécurité FirstAdmin");

        // 4. init user
        $user = new SecurUser();

        // 5. construction du formulaire d'inscription
        $form = $this->formInscription($user);
        $form->handleRequest($request);

        // 6. Traitement du formulaire Si il est soumis
        if ($form->isSubmitted() && $form->isValid()) {

            // 6.1. fabrication du codeVerif
            $codeVerif = $this->generateVerificationCode();

            // 6.2. fabrication du codeUser
            $codeUser = $this->generateUserHash($user);

            // 6.3. renseigne l'objet user
            $user->setActif(0);
            $user->setRoles(['ROLE_ADMIN']);
            $user->setPassword(
                $passwordHasher->hashPassword(
                    $user,
                    $form->get('password')->getData()
                )
            );
            $user->setDateCrea(new \DateTime("NOW"));
            $user->setDateModif(new \DateTime("NOW"));

            // 6.4. config suivant la pref
            $prefUser = $form->get('pref')->getData();
            if ($prefUser == "email") {
                $user->setCodeVerif($codeVerif);
                $this->sendMailVerification($user, $codeVerif);
                $this->addFlash('success', 'Un email contenant la suite de la procédure d\'inscription vient de vous être envoyé.');
                $this->stats->enregistreStat("Action secur_configFirstAdmin Inscription mail");
                $prefUser = "email";
            } else {
                $user->setCodeTelVerif($codeVerif);
                $this->sendSMSVerification($user, $codeVerif);
                $this->addFlash('success', 'Un SMS contenant la suite de la procédure d\'inscription vient de vous être envoyé.');
                $this->stats->enregistreStat("Action secur_configFirstAdmin Inscription sms");
                $prefUser = "sms";
            }

            // 6.5. enregistre l'objet user dans la base
            $this->em->persist($user);
            $this->em->flush();

            // 6.6. Création de l'utilisateur technique
            $this->createTechnicalUser($passwordHasher);

            return $this->redirectToRoute('secur_preinscription', ['prefUser' => $prefUser]);

        }

        // 7. affichage de la page
        return $this->render('security/pages/premiereconnexion.html.twig', [
            'controller_name' => 'secur_firstAdmin',
            'user' => $user,
            'form' => $form->createView(),
            'isAdmin' => $this->ifNoAdmin(),
        ]);

    }

    #[Route(path: '/preinscription/{prefUser}', name: 'secur_preinscription')]
    public function secur_preinscription($prefUser): Response
    {
        // 1. test si banni
        if( $this->ifBanniUser() != ""){
            // 1. enregistre la visite de la page
            $this->stats->enregistreStat("Page secur_preinscription redirection banni");
            // 2. Redirige vers banni
            return $this->redirectToRoute($this->ifBanniUser());
        }

        // 2. enregistre la visite de la page
        $this->stats->enregistreStat("Sécurité Préinscription");

        // 3. Affiche la Page
        return $this->render('security/pages/preinscription.html.twig', [
            'controller_name' => 'secur_preinscription',
            'prefUser' => $prefUser,
        ]);
    }

    #[Route(path: '/activation/{username}/{hash}', name: 'secur_activationCode')]
    public function secur_activationCode($username, $hash, Request $request): Response
    {
        // Vérification si l'utilisateur est banni
        if ($banniRoute = $this->ifBanniUser()) {
            $this->stats->enregistreStat("Sécurité ActivationCode - Redirection banni");
            return $this->redirectToRoute($banniRoute);
        }

        $session = $request->getSession();
        $user = $this->userRepo->findPseudo($username);

        if (!$user) {
            throw $this->createNotFoundException('Utilisateur non trouvé');
        }

        $computedHash = $this->generateUserHash($user[0]);

        if ($computedHash !== $hash) {
            $this->handleFailedAttempt($session, 'Sécurité ActivationCode - Erreur url');
            return $this->render('security/pages/activationError.html.twig', [
                'controller_name' => 'secur_activationCode',
                'prefUser' => $user[0]->getPref(),
            ]);
        }

        $form = $this->formVerifCodeEmail($user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $task = $form->getData();
    
            if ($this->handleFormSubmission($user[0], $task, $session)) {
                return $this->redirectToRoute('secur_login');
            }
        }

        $this->stats->enregistreStat("Sécurité ActivationCode");

        return $this->render('security/pages/activation.html.twig', [
            'controller_name' => 'secur_activationCode',
            'user' => $user[0],
            'form' => $form->createView(),
            'request' => $request,
        ]);
    }    


    #[Route(path: '/oubli', name: 'secur_oubli')]
    public function secur_oubli(Request $request): Response
    {
        if ($banniRoute = $this->ifBanniUser()) {
            $this->stats->enregistreStat("Sécurité Oubli - redirection banni");
            return $this->redirectToRoute($banniRoute);
        }

        $user = new SecurUser();
        $this->stats->enregistreStat("Sécurité Oubli");

        $form = $this->formOubliId($user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $session = $request->getSession();
            $procedure = $this->processOubliForm($user, $session);

            if ($procedure) {
                return $this->redirectToRoute('secur_oubliOk', ['procedure' => $procedure]);
            }
        }

        return $this->render('security/pages/oubli.html.twig', [
            'controller_name' => 'secur_oubli',
            'user' => $user,
            'form' => $form->createView(),
        ]);
    }

    #[Route(path: '/oubli/actif/{procedure}', name: 'secur_oubliOk')]
    public function secur_oubliOk(string $procedure): Response
    {
        // Vérifier si l'utilisateur est banni
        $banniRoute = $this->ifBanniUser();
        if ($banniRoute != "") {
            // Enregistrer la visite et rediriger si banni
            $this->stats->enregistreStat("Sécurité OubliOk - redirection banni");
            return $this->redirectToRoute($banniRoute);
        }

        // Enregistrer la visite
        $this->stats->enregistreStat("Sécurité OubliOk");

        // Afficher la page
        return $this->render('security/pages/oubliok.html.twig', [
            'controller_name' => 'secur_oubliOk',
            'procedure' => $procedure,
        ]);
    }

    #[Route(path: '/reinit/{idUser}_{hash}', name: 'secur_reinitMdp')]
    public function secur_reinitMdp(int $idUser, string $hash, Request $request, UserPasswordHasherInterface $passwordHasher): Response
    {
        // Vérifier si l'utilisateur est banni
        $banniRoute = $this->ifBanniUser();
        if ($banniRoute != "") {
            $this->stats->enregistreStat("Sécurité ReinitMdp - redirection banni");
            return $this->redirectToRoute($banniRoute);
        }
    
        $session = $request->getSession();
        $user = $this->userRepo->find($idUser);
    
        if ($user) {
            $codeUser = $this->generateUserHash($user);
    
            if ($codeUser !== $hash) {
                return $this->handleInvalidHash($session);
            } else {
                return $this->handleValidHash($user, $request, $passwordHasher);
            }
        } else {
            return $this->handleInvalidUser($session);
        }
    }


    #[Route(path: '/bann', name: 'secur_banni')]
    public function secur_banni(Request $request): Response
    {
        // Récupération de l'adresse IP
        $ipAddress = $request->getClientIp();
    
        // Vérification si l'IP est bannie
        $bann = $this->ipbannRepo->findIP($ipAddress);
        
        if (count($bann) == 0) {
            $this->stats->enregistreStat("Sécurité Banni - redirection index");
            return $this->redirectToRoute('front_index');
        }
    
        $this->stats->enregistreStat("Sécurité Banni");
    
        $session = $request->getSession();
        $session->set('nbrEssai', -1);
    
        return $this->render('security/pages/banni.html.twig', [
            'controller_name' => 'secur_banni',
            'admins' => $this->userRepo->findAllAdmins(),
            'bann' => $bann[0],
        ]);
    }


    #[Route(path: '/inscription', name: 'secur_inscription')]
    public function secur_inscription(Request $request, UserPasswordHasherInterface $passwordHasher): Response
    {
        if ($banniRoute = $this->ifBanniUser()) {
            $this->stats->enregistreStat("Sécurité inscription - redirection banni");
            return $this->redirectToRoute($banniRoute);
        }

        $this->stats->enregistreStat("Sécurité inscription");

        $user = new SecurUser();
        $form = $this->formInscription($user);
        $form->handleRequest($request);
    
        if ($form->isSubmitted() && $form->isValid()) {
            $codeVerif = $this->generateVerificationCode();
            $codeUser = $this->generateUserHash($user);
    
            $user->setActif(0);
            $user->setRoles(['ROLE_USER']);
            $user->setPassword(
                $passwordHasher->hashPassword(
                    $user,
                    $form->get('password')->getData()
                )
            );
            $user->setDateCrea(new \DateTime("NOW"));
            $user->setDateModif(new \DateTime("NOW"));
    
            $prefUser = $form->get('pref')->getData();
            if ($prefUser == "email") {
                $user->setCodeVerif($codeVerif);
                $this->sendVerificationEmail($user, $codeUser);
                $this->addFlash('success', 'Un email contenant la suite de la procédure d\'inscription vient de vous être envoyé.');
                $this->stats->enregistreStat("Sécurité inscription - Inscription email");
            } else {
                $user->setCodeTelVerif($codeVerif);
                $this->sendVerificationSms($user, $codeUser);
                $this->addFlash('success', 'Un SMS contenant la suite de la procédure d\'inscription vient de vous être envoyé.');
                $this->stats->enregistreStat("Sécurité inscription - Inscription sms");
            }
    
            $this->em->persist($user);
            $this->em->flush();
    
            // 6.12. redirection vers secur_preinscription 
            return $this->redirectToRoute('secur_preinscription', array('prefUser' => $prefUser));
        }
    
        return $this->render('security/pages/inscription.html.twig', [
            'controller_name' => 'secur_firstAdmin',
            'user' => $user,
            'form' => $form->createView(),
            'isAdmin' => $this->ifNoAdmin(),
        ]);
    }


    #[Route(path: '/invitation/{username}/{hash}', name: 'secur_invitationCode')]
    public function secur_invitationCode(string $username, string $hash, Request $request, UserPasswordHasherInterface $passwordHasher): Response 
    {
        if ($this->ifBanniUser() != "") {
            $this->stats->enregistreStat("Sécurité invitationCode - redirection banni");
            return $this->redirectToRoute($this->ifBanniUser());
        }
    
        $session = $request->getSession();
        $user = $this->userRepo->findPseudo($username);
    
        if (!$user) {
            throw $this->createNotFoundException('Utilisateur non trouvé.');
        }
    
        $calculatedHash = $this->generateUserHash($user[0]);
    
        if ($calculatedHash !== $hash) {
            $this->incrementAttempts($session);
            if ($this->hasExceededAttempts($session)) {
                $this->banIp($request->getClientIp(), "Nombre d'essai dépassé lors de l'activation du compte.");
                return $this->redirectToRoute('secur_banni');
            }
            $this->addFlash('error', 'Erreur sur l\'adresse URL. Il vous reste ' . $this->remainingAttempts($session) . ' essai(s).');
            $this->stats->enregistreStat("Sécurité invitationCode - Erreur URL");
            return $this->render('blog/security/activationError.html.twig', [
                'controller_name' => 'secur_activationErrorCode',
            ]);
        }
    
        $form = $this->formInvitationVerifCodeEmail($user[0]);
        $form->handleRequest($request);
    
        if ($form->isSubmitted() && $form->isValid()) {
            if ($this->hasExceededAttempts($session)) {
                $this->banIp($request->getClientIp(), "Nombre d'essai dépassé lors de l'invitation du compte.");
                return $this->redirectToRoute('secur_banni');
            }
    
            if ($user[0]->getCodeVerif() !== $form->get('codeVerif')->getData()) {
                $this->incrementAttempts($session);
                $this->addFlash('error', 'Le code saisi est incorrect. Il vous reste ' . $this->remainingAttempts($session) . ' essai(s).');
                $this->stats->enregistreStat("Sécurité invitationCode - Erreur code");
            } else {
                $this->activateUser($user[0], $passwordHasher, $form->get('password')->getData());
                $session->set('nbrEssai', -1);
                $this->addFlash('success', 'Votre compte est actif ! Connectez-vous.');
                $this->stats->enregistreStat("Sécurité invitationCode - Success code");
                return $this->redirectToRoute('blog_login');
            }
        }
    
        $this->stats->enregistreStat("Sécurité invitationCode");
        return $this->render('security/pages/invitation.html.twig', [
            'controller_name' => 'secur_invitationCode',
            'user' => $user[0],
            'form' => $form->createView(),
        ]);
    }


    



    /** Fonctions admin *********************************************************** */

    /** liste des users */
    #[Route(path: '/admin/user', name: 'admin_user')]
    public function admin_user(UserInterface $user): Response
    {
        // 1. enregistre la visite de la page
        $this->stats->enregistreStat("Sécurité Liste User");

        // récupère le nombre d'admin
        $nbrAll = count($this->userRepo->findAllOrderByDateCreaDesc());
        $nbrAdmin = count($this->userRepo->findAllAdminsByDateCreaDesc());
        $nbrTech = count($this->userRepo->findAllTechniciensByDateCreaDesc());
        $nbrCorrecteur = count($this->userRepo->findAllCorrecteursByDateCreaDesc());
        $nbrMembre = count($this->userRepo->findAllMembresByDateCreaDesc());
        $nbrInactif = count($this->userRepo->findAllInactifsByDateCreaDesc());

        // affiche la page
        return $this->render('admin/pages/users/users.html.twig', [
            'controller_name' => 'admin_user',
            'user' => $user,
            'nbrAll' => $nbrAll, 
            'nbrAdmin' => $nbrAdmin, 
            'nbrTech' => $nbrTech, 
            'nbrCorrecteur' => $nbrCorrecteur, 
            'nbrMembre' => $nbrMembre, 
            'nbrInactif' => $nbrInactif, 
        ]);

    }

    /** modifier un user */
    #[Route(path: '/admin/user/edit/{id}', name: 'admin_user_edit', methods: ['GET', 'POST'])]
    public function admin_user_edit(UserInterface $user): Response
    {
        // 2. enregistre la visite de la page
        $this->stats->enregistreStat("Page admin_user_edit");

        $utilisateurs = $this->userRepo->findAll();

        return $this->render('admin/pages/users/users_edit.html.twig', [
            'controller_name' => 'admin_user_edit',
            'user' => $user, 
            'utilisateurs' => $utilisateurs, 
        ]);

    }

    /** supprimer un user */
    #[Route('/admin/user/supprime/{id}', name: 'admin_user_delete', methods: ['GET', 'POST'])]
    public function admin_user_delete(Request $request, SecurUser $utilisateur): Response
    {
        if ($this->isCsrfTokenValid('delete'.$utilisateur->getId(), $request->request->get('_token'))) {


            $this->em->remove($utilisateur);
            $this->em->flush();
        }

        return $this->redirectToRoute('admin_user');
    }


    /** Fonctions admin AJAX *********************************************************** */
    
    /** Affiche les users */
    #[Route('/admin/user/affiche', name: 'admin_user_affiche', methods: ['POST'])]
    public function admin_user_affiche(Request $request): Response
    {
        // // 2. création de l'objet catégorie
        // $utilisateur = new SecurUser();

        // // 2. recupération du formulaire
        // $form = $this->formNewUser($utilisateur);
        // $form->handleRequest($request);

        // // 6. Si le formulaire est soumis
        // if ($form->isSubmitted() && $form->isValid()) {
        //     dump("submit traitement dfsdfsdfds");
        // }else{
        //     dump("45454545");
        // }

        // 1. recupère la cible
        $cible = $request->request->get('cible');

        // 2. enregistre la visite de la page
        $this->stats->enregistreStat("Admin User - Affiche ".$cible);

        // recupère les users
        if ($cible == "all"){
            $utilisateurs = $this->userRepo->findAllOrderByDateCreaDesc();
        }
        else if($cible == "admin"){
            $utilisateurs = $this->userRepo->findAllAdminsByDateCreaDesc();
        }
        else if($cible == "correcteur"){
            $utilisateurs = $this->userRepo->findAllCorrecteursByDateCreaDesc();
        }
        else if($cible == "technicien"){
            $utilisateurs = $this->userRepo->findAllTechniciensByDateCreaDesc();
        }
        else if($cible == "membre"){
            $utilisateurs = $this->userRepo->findAllMembresByDateCreaDesc();
        }
        else{
            $utilisateurs = $this->userRepo->findSearchMembre($cible);
        }
        

        // affiche la page
        return $this->render('admin/pages/users/cases/result_users.html.twig', [
            'controller_name' => 'admin_user_affiche',
            'utilisateurs' => $utilisateurs,
        ]);

    }

    /** Affiche un formulaire de nouvel utilisateur */
    #[Route(path: '/admin/user/new', name: 'admin_user_new')]
    public function admin_user_new(UserInterface $user, Request $request, UserPasswordHasherInterface $passwordHasher): Response
    {
        // 1. enregistre la visite de la page
        $this->stats->enregistreStat("Admin User - New User");

        // recupere le nombre de membre + 1
        $countUser = count($this->userRepo->findAllOrderByDateCreaDesc())+1;
        // construit un mot de passe temporaire
        $passTemp = $this->generateVerificationCode();

        // 2. création de l'objet catégorie
        $utilisateur = new SecurUser();

        // pre remplissage
        $utilisateur->setUsername("membre_".$countUser);
        $utilisateur->setPassword($passTemp);
        $utilisateur->setCodeVerif($passTemp);
        $utilisateur->setActif(0);
        $utilisateur->setDateCrea(new \DateTime("NOW"));
        
        // 6.5. enregistre l'objet user dans la base
        // $this->em->persist($utilisateur);
        // $this->em->flush();

        // 2. recupération du formulaire
        $form = $this->formNewUser($utilisateur);
        $form->handleRequest($request);

        // 6. Si le formulaire est soumis
        if ($form->isSubmitted() && $form->isValid()) {
            $errors = [];

            // Vérification du pseudo
            $pseudo = $form->get('username')->getData();
            $userPseudo = $this->userRepo->findOneBy(['username' => $pseudo]);
            if ($userPseudo) {
                $errors[] = "Le pseudo que vous avez choisi est déjà utilisé par un membre. Choisissez en un autre!";
            }

            // Vérification de l'email
            $email = $form->get('email')->getData();
            $userEmail = $this->userRepo->findOneBy(['email' => $email]);
            if ($userEmail) {
                $errors[] = "L'adresse e-mail que vous avez fournie est déjà utilisée par un autre utilisateur.";
            }

            // Si des erreurs sont trouvées, renvoyer une réponse JSON avec les erreurs
            if (count($errors) > 0) {
                return new JsonResponse(['errors' => $errors], JsonResponse::HTTP_BAD_REQUEST);
            }

            // sinon il n y a pas d erreur
            // enregistre le nouvel utilisateur
            $utilisateur->setPassword(
                $passwordHasher->hashPassword(
                    $utilisateur,
                    $form->get('password')->getData()
                )
            );
            $utilisateur->setDateCrea(new \DateTime("NOW"));
            $utilisateur->setRoles($form->get('roles')->getData());

            // 6.4. config suivant la pref
            $codeVerif = $this->generateVerificationCode();
            $prefUser = $form->get('pref')->getData();
            if($prefUser == "email"){
                $utilisateur->setCodeVerif($codeVerif);
                $utilisateur->setCodeTelVerif(null);
            }
            else{
                $utilisateur->setCodeTelVerif($codeVerif);
                $utilisateur->setCodeVerif(null);
            }

            // 6.5. enregistre l'objet user dans la base
            $this->em->persist($utilisateur);
            $this->em->flush();

            // suivant les prefs
            if($prefUser == "email"){
                // envoi un email 
                // 6.2. fabrication du codeUser
                //$codeUser = $this->generateUserHash($utilisateur);

                $monuser = $this->userRepo->findPseudo($utilisateur->getUsername());

                // 5. construction du Hash du compte user
                $codeUser = $this->generateUserHash($monuser[0]);

                // 6.6.1. configure l email
                $dest = $utilisateur->getEmail();
                $sujet = $user->getUsername()." vient de vous inscrire sur ".$this->getParameter('env.nomSite');
                $message = '
                    codeVerif : '.$codeVerif.'
                    passPro : '.$form->get('password')->getData().'
                ';
                $template = "security/emails/mailIscriptionViaAdmin.html.twig";
                $titre = $user->getUsername()." vient de vous inscrire sur ".$this->getParameter('env.nomSite');
                $context = [
                    'titreDansLeMail' => $titre,
                    'pseudo' => $utilisateur->getUsername(),
                    'codeVerif' => $utilisateur->getCodeVerif(),
                    'codeUser' => $codeUser,
                    'passPro' => $form->get('password')->getData(),
                    'lienActivation' => "https://".$this->getParameter('env.urlSite').$this->raccInvitation.$utilisateur->getUsername()."/".$codeUser,
                ];

                // 6.6.2. envoi un email pour verifier l email
                $this->sendMailx->envoiEmail($dest, $sujet, $message, $template, $titre, $context);

                // 6.6.3. prepare le message flash success
                $this->addFlash('success', 'Nouvel utilisateur enregistré.');
    
                // 6.6.4. enregistre la visite de la page
                $this->stats->enregistreStat("Action secur_configFirstAdmin Inscription mail");

                // 6.6.5. init pref
                $prefUser = "email";

                return new JsonResponse(['success' => 'User created successfully']);
            }
            else{
                // envoi un SMS
                // 6.6.1. configure le sms
                $message = $user->getUsername().' vous invite a finaliser votre inscription sur https://'.$this->getParameter('env.urlSite').$this->raccInvitation.$utilisateur->getUsername().'/'.$codeUser .', avec le pass provisoire : '.$form->get('password')->getData().' et le code : '.$codeVerif;

                // 6.6.2. envoi un sms pour verifier le telephone
                $this->sendSmsx->moucheSMS($message, $form->get('telephone')->getData());

                // 6.6.3. prepare le message flash success
                $this->addFlash('success', 'Nouvel utilisateur enregistré.');
    
                // 6.6.4. enregistre la visite de la page
                $this->stats->enregistreStat("Action secur_configFirstAdmin Inscription sms");

                // 6.6.5. init pref
                $prefUser = "sms";

                return new JsonResponse(['success' => 'User created successfully']);
            }

        }

        return $this->render('admin/pages/users/cases/user_new.html.twig', [
            'controller_name' => 'admin_user_new',
            'user' => $user, 
            'utilisateur' => $utilisateur, 
            'form' => $form->createView(),
        ]);

    }


    /** Fonctions récurentes *********************************************************** */

    // ifNoAdmin 
    public function ifNoAdmin()
    {
        dump($this->userRepo->isAdminExist());
        // Vérifie s'il existe au moins un admin actif
        return count($this->userRepo->isAdminExist()) ? null : 'secur_firstAdmin';
    } 

    // ifBanniUser
    public function ifBanniUser()
    {
        // recupere l'ip user
        $ip = $_SERVER['REMOTE_ADDR'];

        // verifie si l ip est banni
        $banni = $this->ipbannRepo->findIP($ip);
        if (count($banni) > 0){
            $target = 'secur_banni';
        }
        // sinon l'ip est valide
        else{
            $target = '';
        }

        return $target;
    }

    // fabrication d'un codeVerif
    public function codeVerif()
    {
        $code = rand(0, 9).rand(0, 9).rand(0, 9).rand(0, 9).rand(0, 9).rand(0, 9);
        return $code;
    }

    // makehash ****
    public function makehash($user)
    {
        $hash = md5($user->getUsername()."polopKey".$user->getEmail());
        return $hash;
    }

    // Génération d'un code de vérification
    public function generateVerificationCode()
    {
        return random_int(100000, 999999);
    }

    // Génération d'un hachage utilisateur
    public function generateUserHash($user)
    {
        return md5($user->getUsername() . "polopKey" . $user->getEmail());
    }

    // Envoi d'un e-mail de vérification
    public function sendMailVerification($user, $codeVerif)
    {
        // 1. configure l email
        $dest = $user->getEmail();
        $sujet = "Inscription de l'administrateur sur ".$this->getParameter('env.nomSite');
        $message = '
            codeVerif : '.$codeVerif.'
        ';
        $template = "security/emails/mailPremiereConnexion.html.twig";
        $titre = "Inscription de l'administrateur sur ".$this->getParameter('env.nomSite');
        $context = [
            'titreDansLeMail' => $titre,
            'pseudo' => $user->getUsername(),
            'codeVerif' => $user->getCodeVerif(),
            'codeUser' => $this->generateUserHash($user),
            'lienActivation' => "https://".$this->getParameter('env.urlSite').$this->raccActivation.$user->getUsername()."/".$this->generateUserHash($user),
        ];

        // 2. Envoi de l'e-mail...
        $this->sendMailx->envoiEmail($dest, $sujet, $message, $template, $titre, $context);
    }

    // Envoi d'un SMS de vérification
    public function sendSMSVerification($user, $codeVerif)
    {
        // 1. configure le sms
        $message = 'Finalisez votre inscription sur https://' . $this->getParameter('env.urlSite') . $this->raccActivation . $user->getUsername() . '/' . $this->generateUserHash($user) . ', avec le code : ' . $codeVerif;

        // 2. envoi un sms pour verifier le telephone
        $this->sendSmsx->moucheSMS($message, $form->get('telephone')->getData());
    }

    // Création de l'utilisateur technique
    public function createTechnicalUser($passwordHasher)
    {
        $tech = new SecurUser();

        // Initialisation de l'utilisateur technique...
        $tech->setUsername("technique");
        $tech->setRoles(['ROLE_TECH']);
        $tech->setPassword(
            $passwordHasher->hashPassword(
                $tech,
                "fdsfds!f4ds5"
            )
        );
        $tech->setEmail("admin@webgiciel.com");
        $tech->setTelephone("0667876149");
        $tech->setCgu(1);
        $tech->setActif(1);
        $tech->setDateCrea(new \DateTime("NOW"));
        $tech->setDateModif(new \DateTime("NOW"));
        $tech->setPref("email");

        $this->em->persist($tech);
        $this->em->flush();

        $this->sendTechNotificationEmail($tech);
    }

    // Méthode pour envoyer un e-mail au technicien
    public function sendTechNotificationEmail($tech)
    {
        $dest = $tech->getEmail();
        $sujet = "Nouveau site à superviser : " . $this->getParameter('env.nomSite');
        $template = "security/emails/technicien.html.twig";
        $titre = $this->getParameter('env.nomSite') . " est à superviser";
        $context = [
            'titreDansLeMail' => $titre,
            'pseudo' => $tech->getUsername(),
            'urlSite' => "https://" . $this->getParameter('env.urlSite'),
        ];

        // Envoi de l'e-mail
        $this->sendMailx->envoiEmail($dest, $sujet, '', $template, $titre, $context);
    }

    // Logique pour gérer les tentatives de connexion échouées
    private function handleFailedAttempt(SessionInterface $session, $statMessage)
    {
        $currentAttempts = $session->get('nbrEssai', 0) + 1;
        $session->set('nbrEssai', $currentAttempts);
    
        if ($currentAttempts >= $this->limiteEssai) {
            $this->banUserForExcessiveAttempts();
            $this->stats->enregistreStat($statMessage . " - Redirection banni");
            return $this->redirectToRoute('secur_banni');
        }
    
        $this->addFlash('error', 'Attention, il y a une erreur sur l\'adresse url que vous avez saisi ! Il vous reste ' . abs($this->limiteEssai - $currentAttempts) . ' essai(s)');
        $this->stats->enregistreStat($statMessage);
    }

    // Logique pour gérer la soumission du formulaire d'activation
    private function handleFormSubmission($user, $task, SessionInterface $session): bool
    {
        $pref = $user->getPref();
        $codeVerif = $pref === "email" ? $user->getCodeVerif() : $user->getCodeTelVerif();
    
        if ($codeVerif !== $task["codeVerif"]) {
            $this->handleFailedAttempt($session, "Sécurité ActivationCode - Erreur code " . ($pref === "email" ? "email" : "sms"));
            return false;
        }
    
        $user->setActif(1);
        $user->setDateModif(new \DateTime("NOW"));
        $pref === "email" ? $user->setCodeVerif(null) : $user->setCodeTelVerif(null);
    
        $this->em->persist($user);
        $this->em->flush();
    
        $session->set('nbrEssai', -1);
    
        $this->addFlash('success', 'Votre compte est actif ! Loguez-vous pour entrer.');
        $this->stats->enregistreStat("Sécurité ActivationCode - Success code " . ($pref === "email" ? "email" : "sms"));
        return true;
    }

    // Logique pour bannir un utilisateur en cas de tentatives excessives
    private function banUserForExcessiveAttempts()
    {
        $ipBann = new SecurIpbann();
        $ipBann->setIp($_SERVER['REMOTE_ADDR']);
        $ipBann->setReproche("Nombre d'essai dépassé lors de l'activation du compte.");
        $ipBann->setDateCrea(new \DateTime("NOW"));
    
        $this->em->persist($ipBann);
        $this->em->flush();
    }

    // traite les données du formulaire de réinitialisation de mot de passe
    private function processOubliForm(SecurUser $user, SessionInterface $session): ?string
    {
        $taskPseudo = $user->getUsername();
        $taskEmail = $user->getEmail();
        $taskTelephone = $user->getTelephone();

        $userRecup = $taskEmail ? $this->userRepo->findPseudoEmail($taskPseudo, $taskEmail) : $this->userRepo->findPseudoTel($taskPseudo, $taskTelephone);
        $procedure = $taskEmail ? "email" : "sms";

        if (count($userRecup) > 0) {
            $this->handleUserRecovery($userRecup[0], $procedure, $taskEmail ? $user->getEmail() : $user->getTelephone());
            return $procedure;
        }

        $this->handleFailedAttempt($session, "Sécurité Oubli - Identifiants non reconnus");
        return null;
    }

    // gère la procédure de récupération de l'utilisateur
    private function handleUserRecovery($user, $procedure, $contact)
    {
        $codeVerif = $this->generateVerificationCode();
        $codeUser = $this->generateUserHash($user);
    
        $user->setActif(0);
        $procedure === "email" ? $user->setCodeVerif($codeVerif) : $user->setCodeTelVerif($codeVerif);
    
        $this->em->persist($user);
        $this->em->flush();
    
        if ($procedure === "email") {
            $this->sendRecoveryEmail($user, $codeUser, $codeVerif);
        } else {
            $this->sendRecoverySms($user, $codeUser, $codeVerif);
        }
    }

    // envoie un email de récupération à l'utilisateur avec le code de vérification et les instructions pour réinitialiser le mot de passe
    private function sendRecoveryEmail(SecurUser $user, string $codeUser, string $codeVerif): void
    {
        // 1. configure l email
        $dest = $user->getEmail();
        $sujet = "Réinitialisation des identifiants de ".$user->getUsername()." sur ".$this->getParameter('env.nomSite');
        $message = '
            codeVerif : '.$codeVerif.'
        ';
        $template = "security/emails/mailOubli.html.twig";
        $titre = "Réinitialisation des identifiants de ".$user->getUsername()." sur ".$this->getParameter('env.nomSite');
        $context = [
            'titreDansLeMail' => "Réinitialisation des identifiants de ".$user->getUsername()." sur ".$this->getParameter('env.nomSite'),
            'pseudo' => $user->getUsername(),
            'idUser' => $user->getId(),
            'codeVerif' => $user->getCodeVerif(),
            'codeUser' => $codeUser,
            'urlSite' => "https://".$this->getParameter('env.urlSite'),
            'nomSite' => $this->getParameter('env.urlSite'),
        ];

        // 2. Envoi de l'e-mail...
        $this->sendMailx->envoiEmail($dest, $sujet, $message, $template, $titre, $context);
    }

    // envoie un SMS de récupération à l'utilisateur avec le code de vérification et les instructions pour réinitialiser le mot de passe
    private function sendRecoverySms(SecurUser $user, string $codeUser, string $contact): void
    {
        $message = 'Reinitialisation vos identifiants sur '.$this->getParameter('env.nomSite').'. Rendez-vous sur https://'.$this->getParameter('env.urlSite').'/reinit/'.$user->getId().'_'.$codeUser .', avec le code : '.$user->getCodeTelVerif();
        $this->sendSmsx->moucheSMS($message, $user->getTelephone());
    }

    // gère les cas où le hachage dans l'URL n'est pas valide
    private function handleInvalidHash(SessionInterface $session): Response
    {
        $this->incrementAttempt($session);
    
        if ($session->get('nbrEssai') > $this->limiteEssai) {
            $this->banUser("Nombre d'essai dépassé lors de la réinitialisation des identifiants. hash");
            return $this->redirectToRoute('secur_banni');
        } else {
            $remainingAttempts = abs($this->limiteEssai - $session->get('nbrEssai') + 1);
            $this->addFlash('error', "Attention, il y a une erreur sur l'adresse url que vous avez saisi ! Il vous reste $remainingAttempts essai(s)");
            $this->stats->enregistreStat("Sécurité ReinitMdp - Erreur url");
            return $this->render('security/pages/reinitError.html.twig', ['controller_name' => 'secur_reinitMdp']);
        }
    }

    //gère les cas où le hachage dans l'URL est valide
    private function handleValidHash($user, Request $request, UserPasswordHasherInterface $passwordHasher): Response
    {
        $form = $this->formOubliReinit();
        $form->handleRequest($request);
    
        if ($form->isSubmitted() && $form->isValid()) {
            return $this->resetUserPassword($user, $form, $passwordHasher);
        }
    
        $this->stats->enregistreStat("Sécurité ReinitMdp");
        return $this->render('security/pages/reinit.html.twig', [
            'controller_name' => 'secur_reinitMdp',
            'form' => $form->createView(),
        ]);
    }

    // réinitialise le mot de passe de l'utilisateur avec celui fourni dans le formulaire
    private function resetUserPassword($user, $form, UserPasswordHasherInterface $passwordHasher): Response
    {
        $user->setActif(1);
        $user->setPassword($passwordHasher->hashPassword($user, $form->get('password')->getData()));
        $user->setCodeVerif(null);
        $user->setCodeTelVerif(null);
        $user->setDateModif(new \DateTime("NOW"));
    
        $this->em->persist($user);
        $this->em->flush();
    
        $this->addFlash('success', 'Votre mot de passe est modifié! Vous pouvez vous identifier pour continuer..');
        $this->stats->enregistreStat("Sécurité ReinitMdp - Mot de passe est modifié");
    
        return $this->redirectToRoute('secur_login');
    }
    
    private function handleInvalidUser(SessionInterface $session): Response
    {
        $this->incrementAttempt($session);
    
        if ($session->get('nbrEssai') > $this->limiteEssai) {
            $this->banUser("Nombre d'essai dépassé lors de la réinitialisation des identifiants.");
            return $this->redirectToRoute('secur_banni');
        } else {
            $remainingAttempts = abs($this->limiteEssai - $session->get('nbrEssai') + 1);
            $this->addFlash('error', "Attention, il y a une erreur sur l'adresse url que vous avez saisi ! Il vous reste $remainingAttempts essai(s)");
            $this->stats->enregistreStat("Sécurité ReinitMdp - Erreur url");
            return $this->render('security/pages/reinitError.html.twig', ['controller_name' => 'secur_reinitMdp']);
        }
    }
    
    private function incrementAttempt(SessionInterface $session): void
    {
        if ($session->get('nbrEssai') == -1) {
            $session->set('nbrEssai', 1);
        } else {
            $newEss = $session->get('nbrEssai') + 1;
            $session->set('nbrEssai', $newEss);
        }
    }
    
    private function banUser(string $reason): void
    {
        $ipVisiteur = $_SERVER['REMOTE_ADDR'];
        $ipBann = new SecurIpbann();
        $ipBann->setIp($ipVisiteur);
        $ipBann->setReproche($reason);
        $ipBann->setDateCrea(new \DateTime("NOW"));
    
        $this->em->persist($ipBann);
        $this->em->flush();
    
        $this->stats->enregistreStat("Sécurité ReinitMdp - Essai dépassé - Redirection banni");
    }
    
    private function incrementAttempts(SessionInterface $session)
    {
        $attempts = $session->get('nbrEssai', -1);
        $session->set('nbrEssai', $attempts + 1);
    }

    private function hasExceededAttempts(SessionInterface $session): bool
    {
        return $session->get('nbrEssai') >= $this->limiteEssai;
    }
    
    private function remainingAttempts(SessionInterface $session): int
    {
        return abs($this->limiteEssai - $session->get('nbrEssai') + 1);
    }
    
    private function banIp(string $ipAddress, string $reason)
    {
        $ipBann = new SecurIpbann();
        $ipBann->setIp($ipAddress);
        $ipBann->setReproche($reason);
        $ipBann->setDateCrea(new \DateTime("NOW"));
    
        $this->em->persist($ipBann);
        $this->em->flush();
    
        $this->stats->enregistreStat("IP Bannie: " . $reason);
    }
    
    private function activateUser(SecurUser $user, UserPasswordHasherInterface $passwordHasher, string $password)
    {
        $user->setActif(1);
        $user->setCgu(1);
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $user->setDateModif(new \DateTime("NOW"));
    
        $this->em->persist($user);
        $this->em->flush();
    }

    private function sendVerificationEmail(SecurUser $user, string $codeUser)
    {
        $dest = $user->getEmail();
        $sujet = "Inscription au blog de " . $this->getParameter('env.nomSite');
        $message = 'Code de vérification : ' . $user->getCodeVerif();
        $template = "security/emails/mailInscription.html.twig";
        $titre = "Inscription au blog de " . $this->getParameter('env.nomSite');
        $context = [
            'titreDansLeMail' => "Inscription au blog de " . $this->getParameter('env.nomSite'),
            'pseudo' => $user->getUsername(),
            'codeVerif' => $user->getCodeVerif(),
            'codeUser' => $codeUser,
            'lienActivation' => "https://" . $this->getParameter('env.urlSite') . $this->raccActivation . $user->getUsername() . "/" . $codeUser,
        ];
    
        $this->sendMailx->envoiEmail($dest, $sujet, $message, $template, $titre, $context);
    }
    
    private function sendVerificationSms(SecurUser $user, string $codeUser)
    {
        $message = 'Finalisez votre inscription sur https://' . $this->getParameter('env.urlSite') . $this->raccActivation . $user->getUsername() . '/' . $codeUser . ', avec le code : ' . $user->getCodeTelVerif();
        $this->sendSmsx->moucheSMS($message, $user->getTelephone());
    }




    // Fonctions de formulaires ******************************************************************************************* **** //

    // formulaire d'Inscription premier admin avec csrf
    public function formFirstAdmin($task){
        // Générez le jeton CSRF
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('username', TextType::class, [
                'label' => 'Choisissez votre pseudo *',
                'required'   => true,
                'help' => 'Votre pseudo ne doit pas contenir de caractères spéciaux, et doit contenir entre 4 et 16 caractères.',
                'attr' => [
                    "class" => "form-control",
                    "onkeypress" => "verifierCaracteres(event); return false;",
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'Attention, les champs mot de passe doivent correspondrent.',
                'options' => [
                    'attr' => [
                        'class' => 'password-field form-control'
                    ]
                ],
                'required' => true,

                'first_options'  => 
                [
                    'label' => 'Choisissez un mot de passe *',
                    'help' => 'Votre mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial, et doit contenir entre 8 et 16 caractères.',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Mot de passe',
                    ],
                    'row_attr' => [
                        'class' => '', 
                    ]
                ],

                'second_options' => 
                [
                    'label' => 'Retaper votre mot de passe *',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Retaper le mot de passe'
                    ],
                ],
            ])

            ->add('email', EmailType::class, [
                'label' => 'Votre mail de contact *',
                'required'   => true,
                'help' => 'Votre mail doit être fonctionnel car il vous permettra d\'activer votre compte.',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Email",
                ]
            ])

            ->add('telephone', TelType::class, [
                'label' => 'Votre téléphone',
                'required'   => false,
                'help' => 'Optionnel',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Téléphone",
                ]
            ])

            ->add('cgu', CheckboxType::class, [
                'label'    => 'J\'accepte les conditions générales d\'utilisation. *',
                'required'   => true,
                'label_attr' => [
                    "class" => "form-check-label text-muted",
                ],
                'attr' => [
                    "class" => "form-check-label text-muted",
                ],
            ])

            ->add('prenom', TextType::class, [
                'label' => 'Prénom',
                'required'   => false,
                'help' => '',
                'attr' => [
                "class" => "form-control",
                    "placeholder" => "Prénom",
                ]
            ])

            ->add('nom', TextType::class, [
                'label' => 'Nom',
                'required'   => false,
                'help' => '',
                'attr' => [
                "class" => "form-control",
                    "placeholder" => "Nom",
                ]
            ])

            ->add('societe', TextType::class, [
                'label' => 'Société',
                'required'   => false,
                'help' => '',
                'attr' => [
                "class" => "form-control",
                    "placeholder" => "Société",
                ]
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Enregistrer', 
                'attr' => [
                    "class" => "btn btn-block btn-primary font-weight-medium auth-form-btn",
                ],
            ])

            ->getForm();

        return $form;
    }

    // formulaire de Vérification du code email avec csrf
    public function formVerifCodeEmail($task){
        // Générez le jeton CSRF
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('codeVerif', TextType::class, [
                'label' => 'Renseignez ici le code reçu par email',
                'required'   => false,
                'attr' => [
                "class" => "form-control",
                    "placeholder" => "Code",
                ]
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Envoyer', 
                'attr' => [
                    "class" => "btn btn-block btn-primary font-weight-medium auth-form-btn",
                ],
            ])

            ->getForm();

        return $form;
    }

    // formulaire d'oubli des identifiants avec csrf
    public function formOubliId($task){
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('username', TextType::class, [
                'label' => 'Renseignez votre pseudo *',
                'required'   => true,
                'attr' => [
                    "class" => "form-control",
                    "onkeypress" => "verifierCaracteres(event); return false;",
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('email', EmailType::class, [
                'label' => 'Renseignez ici votre email de contact',
                'required'   => false,
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Email",
                ]
            ])

            ->add('telephone', TelType::class, [
                'label' => 'Renseignez votre numéro de téléphone',
                'required'   => false,
                'help' => 'Optionnel',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Téléphone",
                ]
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Envoyer', 
                'attr' => [
                    "class" => "btn btn-block btn-primary font-weight-medium auth-form-btn",
                ],
            ])

            ->getForm();

        return $form;
    }

    // formulaire de reinitialisation avec csrf
    public function formOubliReinit(){
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder([
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('username', TextType::class, [
                'label' => 'Renseignez votre pseudo',
                'required'   => false,
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('verifcode', TextType::class, [
                'label' => 'Renseignez le CodeVerif',
                'required'   => false,
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "CodeVerif",
                ]
            ])

            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'Attention, les champs mot de passe doivent correspondrent.',
                'options' => [
                    'attr' => [
                        'class' => 'password-field form-control form-control-lg'
                    ]
                ],
                'required' => false,

                'first_options'  => 
                [
                    'label' => 'Choisissez votre nouveau mot de passe',
                    'help' => 'Votre mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial, et doit contenir entre 8 et 16 caractères.',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Mot de passe *',
                    ],
                    'row_attr' => [
                        'class' => '', 
                    ]
                ],
                
                'second_options' => 
                [
                    'label' => 'Retaper votre nouveau mot de passe',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Retaper le mot de passe'
                    ],
                ],
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Envoyer', 
                'attr' => [
                    "class" => "btn btn-block btn-primary font-weight-medium auth-form-btn",
                ],
            ])

            ->getForm();

        return $form;
    }

    // formulaire d'Inscription 
    public function formInscription($task){
        // Générez le jeton CSRF
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('username', TextType::class, [
                'label' => 'Choisissez votre pseudo *',
                'required'   => true,
                'attr' => [
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'Attention, les champs mot de passe doivent correspondrent.',
                'options' => [
                    'attr' => [
                        'class' => 'form-control'
                    ]
                ],
                'required' => true,

                'first_options'  => 
                [
                    'label' => 'Choisissez un mot de passe',
                    'help' => 'Votre mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial, et doit contenir entre 8 et 16 caractères.',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Mot de passe *',
                    ],
                    'row_attr' => [
                        'class' => '', 
                    ]
                ],

                'second_options' => 
                [
                    'label' => 'Retaper votre mot de passe *',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Retaper le mot de passe'
                    ],
                ],
            ])

            ->add('email', EmailType::class, [
                'label' => 'Votre mail de contact *',
                'required'   => true,
                'help' => 'Votre mail doit être fonctionnel car il vous permettra d\'activer votre compte.',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Email",
                ]
            ])

            ->add('telephone', TelType::class, [
                'label' => 'Téléphone',
                'required'   => false,
                'help' => 'Optionnel',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Téléphone",
                ]
            ])

            ->add('pref', ChoiceType::class, [
                'label'    => 'Choisissez votre préférence de contact *',
                'expanded' => true,
                'multiple' => false,
                'choices'  => [
                    "email" => "email",
                    "téléphone" => "tel",
                ],
            ])

            ->add('cgu', CheckboxType::class, [
                'label'    => ' J\'accepte les conditions générales d\'utilisation. *',
                'required'   => true,
                'label_attr' => [
                ],
                'attr' => [
                    "style" => "padding:0; border-color:#213b52;",
                ],
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Enregistrer', 
                'attr' => [
                    "class" => "btn-get-started btn-primary",
                ],
            ])

            ->getForm();

            return $form;
    }

    // formulaire nouvel utilisateur 
    public function formNewUser($task){
        // Générez le jeton CSRF
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('username', TextType::class, [
                'label' => 'Pseudo provisoire *',
                'required'   => true,
                'help' => ' ',
                'attr' => [
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('password', TextType::class, [
                'label' => 'Mot de passe provisoire',
                'required'   => false,
                'help' => ' ',
                'attr' => [
                    "disabled" => "disabled",
                ]
            ])

            ->add('roles', ChoiceType::class, [
                'label'    => 'Choisissez le grade *',
                'expanded' => false,
                'multiple' => false,
                'choices'  => [
                    "Membre" => "ROLE_USER",
                    "Correcteur" => "ROLE_CORRECTEUR",
                    "Admin" => "ROLE_ADMIN",
                ],
                'attr' => [
                    "class" => "form-select",
                ]
            ])

            ->add('changePAss', CheckboxType::class, [
                'label'    => 'Forcer la modification du mot de passe',
                'required' => true,
                'attr' => array('checked' => 'checked'),
            ])

            ->add('email', EmailType::class, [
                'label' => 'Email de contact *',
                'required'   => true,
                'help' => ' ',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Email",
                ]
            ])

            ->add('telephone', TelType::class, [
                'label' => 'Téléphone',
                'required'   => false,
                'help' => ' ',
                'attr' => [
                    "class" => "form-control",
                    "placeholder" => "Téléphone",
                ]
            ])

            ->add('pref', ChoiceType::class, [
                'label'    => 'Préférence de contact *',
                'expanded' => true,
                'multiple' => false,
                'choices'  => [
                    "email" => "email",
                    "téléphone" => "tel",
                ],
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Enregistrer', 
                'attr' => [
                    "class" => "btn-get-started btn-primary",
                ],
            ])
            ;

        // Apply the data transformer to the roles field
        $form->get('roles')
            ->addModelTransformer(new CallbackTransformer(
                function ($rolesArray) {
                    // transform the array to a string
                    return count($rolesArray) ? $rolesArray[0] : null;
                },
                function ($rolesString) {
                    // transform the string back to an array
                    return [$rolesString];
                }
            ));

        return $form->getForm();
    }
    
    // formulaire de l'invitation et vérification du code email avec csrf
    public function formInvitationVerifCodeEmail($task){
        // Générez le jeton CSRF
        $csrfToken = $this->csrfTokenManager->getToken('form_intention')->getValue();

        $form = $this->createFormBuilder($task, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id' => 'form_intention',
            ])

            ->add('codeVerif', TextType::class, [
                'label' => 'Renseignez ici le code reçu par email',
                'required'   => true,
                'attr' => [
                "class" => "form-control",
                    "placeholder" => "Code",
                ]
            ])

            ->add('username', TextType::class, [
                'label' => 'Modifer votre pseudo',
                'required'   => true,
                'help' => ' ',
                'row_attr' => [
                    'class' => 'mt-3', 
                ],
                'attr' => [
                    "class" => "form-control",
                    "onkeypress" => "verifierCaracteres(event); return false;",
                    "placeholder" => "Pseudo",
                ]
            ])

            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'Attention, les champs mot de passe doivent correspondrent.',
                'options' => [
                    'attr' => [
                        'class' => 'password-field form-control mt-3'
                    ]
                ],
                'required' => true,

                'first_options'  => 
                [
                    'label' => 'Choisissez un mot de passe *',
                    'help' => 'Votre mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial, et doit contenir entre 8 et 16 caractères.',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Mot de passe',
                    ],
                    'row_attr' => [
                        'class' => 'mt-3', 
                    ]
                ],

                'second_options' => 
                [
                    'label' => 'Retaper votre mot de passe *',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'Retaper le mot de passe'
                    ],
                ],
            ])

            ->add('cgu', CheckboxType::class, [
                'label'    => 'J\'accepte les conditions générales d\'utilisation. *',
                'required'   => true,
                'label_attr' => [
                    "class" => "form-check-label text-muted mt-3",
                ],
                'attr' => [
                    "class" => "form-check-label text-muted mt-3",
                ],
            ])

            ->add('save', SubmitType::class, [
                'label' => 'Envoyer', 
                'attr' => [
                    "class" => "btn btn-block btn-primary font-weight-medium auth-form-btn",
                ],
            ])

            ->getForm();

        return $form;
    }


    /** Pages  ************************************************************************* */








    /** Ajax  ************************************************************************* */

    /** 
     * Vérifie si un pseudo est déjà utilisé.
     * 
     * Cette fonction est appelée via une requête AJAX.
     * Elle récupère le pseudo envoyé depuis le formulaire, vérifie son existence dans la base de données,
     * puis renvoie une réponse JSON indiquant si le pseudo est déjà utilisé ou non.
     */
    #[Route(path: '/verifPseudo', name: 'secur_verifPseudo')]
    public function secur_verifPseudo(Request $request): JsonResponse
    {
        // 1. Récupération des données de la requête AJAX
        $pseudo = $request->request->get('pseudo');

        // 2. Vérification de l'existence du pseudo dans la base de données
        $user = $this->userRepo->findPseudo($pseudo);

        // 3. Retourne une réponse JSON avec le nombre d'utilisateurs trouvés avec ce pseudo
        return $this->json(['msg' => count($user)]);

    }

    /** 
     * Vérifie si une adresse email est déjà utilisée.
     * 
     * Cette fonction est appelée via une requête AJAX.
     * Elle récupère l'adresse email envoyée depuis le formulaire, vérifie son existence dans la base de données,
     * puis renvoie une réponse JSON indiquant si l'adresse email est déjà utilisée ou non.
     */
    #[Route(path: '/verifEmail', name: 'secur_verifEmail')]
    public function secur_verifEmail(Request $request): JsonResponse
    {
        // 1. Récupération des données de la requête AJAX
        $email = $request->request->get('mailx');

        // 2. Vérification de l'existence de l'adresse email dans la base de données
        $user = $this->userRepo->findEmail($email);

        // 3. Retourne une réponse JSON avec le nombre d'utilisateurs trouvés avec cette adresse email
        return $this->json(['msg' => count($user)]);
    }





}
