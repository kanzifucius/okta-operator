/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	oktav1alpha1 "github.com/kanzifucius/okta-operator/api/v1alpha1"
	"github.com/okta/okta-sdk-golang/v2/okta"
	oktaquery "github.com/okta/okta-sdk-golang/v2/okta/query"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"net/http/httputil"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"strings"
	"time"
)

const oktaTrustedDomainFinalizer = "cache.example.com/finalizer"

// TrustedDomainReconciler reconciles a TrustedDomain object
type TrustedDomainReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	OktaClient *okta.Client
}

func (r *TrustedDomainReconciler) CreateOktaClient(log logr.Logger, ctx context.Context, secretName string, secretNamespace string) error {
	log.Info(fmt.Sprintf("Getting secret details for Secret %s and namespace %s ", secretName, secretNamespace))
	secret := &v1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)

	if err != nil {
		if errors.IsNotFound(err) {
			return err
		}

	}

	orgUrl, foundToken := secret.Data["OKTA_DOMAIN"]
	if !foundToken {
		return fmt.Errorf("secret %s entrey OKTA_DOMAIN  not found", secretName)
	}

	token, foundOrgUrl := secret.Data["OKTA_DOMAIN_TOKEN"]
	if !foundOrgUrl {
		return fmt.Errorf("secret %s not found OKTA_DOMAIN_TOKEN ", secretName)
	}

	_, clientOkta, err := okta.NewClient(
		context.TODO(),
		okta.WithOrgUrl(string(orgUrl[:])),
		okta.WithToken(string(token[:])),
	)

	if err != nil {

		return fmt.Errorf("failed to create okta cleint %v", err)

	}
	r.OktaClient = clientOkta
	return nil
}

func (r *TrustedDomainReconciler) DeleteOktaOrigin(log logr.Logger, ctx context.Context, originID string) error {
	log.Info(fmt.Sprintf("deleting  trusted domain %s ", originID))
	resp, err := r.OktaClient.TrustedOrigin.DeleteOrigin(ctx, originID)
	if err != nil {
		return err
	}
	log.Info("deleted origin", "originId", resp.Body)

	return nil
}

func (r *TrustedDomainReconciler) CreateOktaOrigin(ctx context.Context, log logr.Logger, name string, domain string) (string, error) {

	log.Info("Creating origin ", "domain", domain, "name", name)
	origin, _, err := r.OktaClient.TrustedOrigin.CreateOrigin(ctx, okta.TrustedOrigin{
		Name:   name,
		Origin: fmt.Sprintf("https://%s", domain),
		Scopes: []*okta.Scope{
			&okta.Scope{
				Type: "CORS",
			},
			&okta.Scope{
				Type: "REDIRECT",
			},
		},
	})
	if err != nil {
		return "", err
	}

	log.Info("Created origin ", "originId", origin.Id, "domain", domain, "name", name)

	return origin.Id, nil
}

func (r *TrustedDomainReconciler) OriginExists(log logr.Logger, ctx context.Context, name string) (bool, string, error) {
	var hostExists = false
	var id = ""
	filerQuery := fmt.Sprintf("name eq \"%s\"", name)
	filter := oktaquery.NewQueryParams(oktaquery.WithFilter(filerQuery))
	trustedOrigin, resp, err := r.OktaClient.TrustedOrigin.ListOrigins(context.TODO(), filter)
	if err != nil {
		response, err := httputil.DumpResponse(resp.Response, true)
		if err != nil {
			log.Error(err, fmt.Sprintf("error getting trusted origins...\n %q", response))
		}

		return hostExists, id, err
	}

	for _, origin := range trustedOrigin {
		if strings.Contains(origin.Name, name) {
			log.Info(fmt.Sprintf("Found trusted oring name %s origin %s", origin.Name, origin.Origin))
			hostExists = true
			id = origin.Id
		}
	}

	return hostExists, id, nil
}

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=okta.com,resources=trusteddomains,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=okta.com,resources=trusteddomains/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=okta.com,resources=trusteddomains/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the TrustedDomain object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *TrustedDomainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	trustedDomain := &oktav1alpha1.TrustedDomain{}
	err := r.Get(ctx, req.NamespacedName, trustedDomain)
	if err != nil {
		if errors.IsNotFound(err) {

			return ctrl.Result{}, nil
		}
	}

	var secretNameSpace string
	if trustedDomain.Spec.SecretsRefNamespace == "" {
		val, ok := os.LookupEnv("NAMESPACE")
		if ok {
			secretNameSpace = val
		}
	} else {
		secretNameSpace = trustedDomain.Spec.SecretsRefNamespace
	}

	err = r.CreateOktaClient(log, ctx, trustedDomain.Spec.SecretsRef, secretNameSpace)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Check if the trustedDomain instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set.

	isTrustedDomainMarkedToBeDeleted := trustedDomain.GetDeletionTimestamp() != nil
	if isTrustedDomainMarkedToBeDeleted {
		if controllerutil.ContainsFinalizer(trustedDomain, oktaTrustedDomainFinalizer) {
			// Run finalization logic for oktaTrustedDomainFinalizer. If the
			// finalization logic fails, don't remove the finalizer so
			// that we can retry during the next reconciliation.
			if err := r.finalize(log, trustedDomain); err != nil {
				return ctrl.Result{}, err
			}

			// Remove oktaTrustedDomainFinalizer. Once all finalizers have been
			// removed, the object will be deleted.
			controllerutil.RemoveFinalizer(trustedDomain, oktaTrustedDomainFinalizer)
			err := r.Update(ctx, trustedDomain)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer for this CR
	if !controllerutil.ContainsFinalizer(trustedDomain, oktaTrustedDomainFinalizer) {
		controllerutil.AddFinalizer(trustedDomain, oktaTrustedDomainFinalizer)
		err = r.Update(ctx, trustedDomain)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	originExists, existingId, err := r.OriginExists(log, ctx, trustedDomain.Name)
	if err != nil {
		log.Error(err, "error getting trusted origin")
		return ctrl.Result{}, err

	}
	if !originExists {
		id, err := r.CreateOktaOrigin(ctx, log, trustedDomain.Name, trustedDomain.Spec.Domain)
		if err != nil {
			log.Error(err, "failed to create okta origin")
			trustedDomain.Status.Conditions = append(trustedDomain.Status.Conditions, metav1.Condition{
				Type:               "Reconciled",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: 0,
				Reason:             "ApiFailure",
				Message:            "",
				LastTransitionTime: metav1.Time{Time: time.Now()},
			})
			return ctrl.Result{Requeue: true}, err
		}

		trustedDomain.Status.TrustedDomainId = id
		trustedDomain.Status.Conditions = append(trustedDomain.Status.Conditions, metav1.Condition{
			Type:               "Reconciled",
			Status:             metav1.ConditionTrue,
			Reason:             "CreatedDomain",
			Message:            "",
			LastTransitionTime: metav1.Time{Time: time.Now()},
		})
	} else {
		trustedDomain.Status.TrustedDomainId = existingId
		trustedDomain.Status.Conditions = append(trustedDomain.Status.Conditions, metav1.Condition{
			Type:               "Reconciled",
			Status:             metav1.ConditionTrue,
			Reason:             "OriginAlreadyExists",
			Message:            "",
			LastTransitionTime: metav1.Time{Time: time.Now()},
		})
	}

	log.Info("Completed reconcile for trustedDomain ", "trustedDomain", trustedDomain)
	err = r.Status().Update(ctx, trustedDomain)
	if err != nil {
		log.Error(err, "Failed to update trustedDomain status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: false}, nil

}

func (r *TrustedDomainReconciler) finalize(log logr.Logger, td *oktav1alpha1.TrustedDomain) error {

	err := r.DeleteOktaOrigin(log, context.TODO(), td.Status.TrustedDomainId)
	if err != nil {
		log.Error(err, "failed to delete trusted origin")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrustedDomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&oktav1alpha1.TrustedDomain{}).WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
