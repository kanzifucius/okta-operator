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
	"github.com/okta/okta-sdk-golang/v2/okta"
	oktaquery "github.com/okta/okta-sdk-golang/v2/okta/query"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	oktav1alpha1 "github.com/kanzifucius/okta-operator/api/v1alpha1"
)

const oktaTrustedDomainFinalizer = "cache.example.com/finalizer"

// TrustedDomainReconciler reconciles a TrustedDomain object
type TrustedDomainReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	OktaClient *okta.Client
}

func (r *TrustedDomainReconciler) DeleteOktaOrigin(ctx context.Context, name string) error {
	log := ctrllog.FromContext(ctx)
	filerQuery := fmt.Sprintf("name co \"%s\"", name)
	filter := oktaquery.NewQueryParams(oktaquery.WithFilter(filerQuery))
	trustedOrigins, _, err := r.OktaClient.TrustedOrigin.ListOrigins(ctx, filter)
	if err != nil {
		return err
	}

	for _, origin := range trustedOrigins {
		if strings.Contains(origin.Name, name) {
			log.Info(fmt.Sprintf("deleting  trusted domain %s id %s", origin.Name, origin.Id))
			resp, err := r.OktaClient.TrustedOrigin.DeleteOrigin(ctx, origin.Id)
			if err != nil {
				return err
			}
			log.Info("deleted origin", "originId", resp)
		}
	}

	return nil
}

func (r *TrustedDomainReconciler) CreateOktaOrigin(ctx context.Context, name string, domain string) (string, error) {
	log := ctrllog.FromContext(ctx)
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

	log.Info("Created origin ", "originId", origin.Id)

	return origin.Id, nil
}

func (r *TrustedDomainReconciler) OriginExists(ctx context.Context, name string) (bool, error) {
	log := ctrllog.FromContext(ctx)
	var hostExists = false
	filerQuery := fmt.Sprintf("name eq \"%s\"", name)
	filter := oktaquery.NewQueryParams(oktaquery.WithFilter(filerQuery))
	trustedOrigin, _, err := r.OktaClient.TrustedOrigin.ListOrigins(context.TODO(), filter)
	if err != nil {
		log.Error(err, "error getting trusted origins")
		return hostExists, err
	}

	for _, origin := range trustedOrigin {
		if strings.Contains(origin.Name, name) {
			log.Info(fmt.Sprintf("Found trusted oring name%s origin %s", origin.Name, origin.Origin))
			hostExists = true
		}
	}

	return hostExists, nil
}

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

	originExists, err := r.OriginExists(ctx, trustedDomain.Name)
	if err != nil {
		log.Error(err, "error getting trusted origin")
		return ctrl.Result{}, err

	}
	if !originExists {
		id, err := r.CreateOktaOrigin(ctx, trustedDomain.Name, trustedDomain.Spec.Domain)
		if err != nil {
			log.Error(err, "Failed to update trustedDomain status")
			return ctrl.Result{Requeue: true}, err
		}
		//condition := status.Condition{
		//	Type:               "ReconcileError",
		//	LastTransitionTime: metav1.Now(),
		//	Message:            issue.Error(),
		//	Reason:             astatus.FailedReason,
		//	Status:             corev1.ConditionTrue,
		//}
		trustedDomain.Status.TrustedDomainId = id
		trustedDomain.Status.Conditions = append(trustedDomain.Status.Conditions, metav1.Condition{
			Type:               "Reconciled",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: 0,
			Reason:             "",
			Message:            "",
		})

	}
	log.Info("Completed reconcile for trustedDomain ", "trustedDomain", trustedDomain)

	err = r.Status().Update(ctx, trustedDomain)
	if err != nil {
		log.Error(err, "Failed to update trustedDomain status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil

}

func (r *TrustedDomainReconciler) finalize(reqLogger logr.Logger, td *oktav1alpha1.TrustedDomain) error {

	err := r.DeleteOktaOrigin(context.TODO(), td.Name)
	if err != nil {
		reqLogger.Error(err, "failed to delete trusted origin")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrustedDomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&oktav1alpha1.TrustedDomain{}).
		Complete(r)
}
