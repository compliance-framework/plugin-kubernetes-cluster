package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/plugin-kubernetes-cluster/internal"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {

	ctx := context.TODO()

	observations, findings, err := l.EvaluatePolicies(ctx, request)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	if err = apiHelper.CreateFindings(ctx, findings); err != nil {
		l.logger.Error("Failed to send compliance findings", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateObservations(ctx, observations); err != nil {
		l.logger.Error("Failed to send compliance observations", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func (l *CompliancePlugin) EvaluatePolicies(ctx context.Context, request *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	startTime := time.Now()
	var errAcc error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	config, err := rest.InClusterConfig()
	if err != nil {
		l.logger.Error("unable to set k8s config", "error", err)
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		l.logger.Error("unable to define a clientset", "error", err)
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}

	clusterData := make(map[string]interface{})

	// ACTIVITY: cluster RBAC
	_, err = clientset.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		l.logger.Info("RBAC not enabled", err)
		clusterData["RBACEnabled"] = false
	} else {
		l.logger.Info("RBAC enabled", err)
		clusterData["RBACEnabled"] = true
	}
	clusterConfigSteps := make([]*proto.Step, 0)
	clusterConfigSteps = append(clusterConfigSteps, &proto.Step{
		Title:       "Fetch cluster configuration from all namespaces",
		Description: "Fetch cluster configuration from all namespaces, using internal k8s API.",
	})
	activities = append(activities, &proto.Activity{
		Title:       "Collect cluster configurations",
		Description: "Collect cluster configuration and prepare collected data for validation in policy engine",
		Steps:       clusterConfigSteps,
	})

	// ACTIVITY: kubeletConfig
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		l.logger.Error("NODE_NAME is not set! Make sure it's correctly passed to the container.")
		errAcc = errors.Join(errAcc, fmt.Errorf("NODE_NAME environment variable is not set"))
		return observations, findings, errAcc
	}
	kubeletConfigApiPath := fmt.Sprintf("nodes/%s/proxy/configz", nodeName)
	l.logger.Info("Fetching node config from:", "path", kubeletConfigApiPath)
	nodeInfo, err := clientset.RESTClient().
		Get().
		RequestURI(fmt.Sprintf("/api/v1/nodes/%s/proxy/configz", nodeName)).
		Do(context.TODO()).Raw()
	if err != nil {
		l.logger.Error("Unable to get nodeInfo", "error", err.Error())
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	// Attempt to unmarshal into a map if it's JSON
	var nodeInfoMap map[string]interface{}
	if err := json.Unmarshal(nodeInfo, &nodeInfoMap); err != nil {
		l.logger.Error("Unable to unmarshal nodeInfo", "error", err.Error())
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	l.logger.Info("Unmarshalled node info", "nodeInfo", nodeInfoMap)
	kubeletConfigSteps := make([]*proto.Step, 0)
	kubeletConfigSteps = append(kubeletConfigSteps, &proto.Step{
		Title:       "Fetched node proxy config",
		Description: "Fetched node proxy config using internal k8s API.",
	})
	if kubeletConfig, exists := nodeInfoMap["kubeletconfig"].(map[string]interface{}); exists {
		clusterData["kubeletConfig"] = kubeletConfig
		kubeletConfigSteps = append(kubeletConfigSteps, &proto.Step{
			Title:       "Fetched kubeletConfig",
			Description: "Fetched kubeletConfig using internal k8s API.",
		})

	}
	activities = append(activities, &proto.Activity{
		Title:       "Collected node proxy config configuration",
		Description: "Collected node proxy config configuration and prepare collected data for validation in policy engine",
		Steps:       kubeletConfigSteps,
	})

	// ACTIVITY: statsSummary
	statsSummaryApiPath := fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", nodeName)
	statsSummary, err := clientset.RESTClient().
		Get().
		RequestURI(statsSummaryApiPath).
		DoRaw(context.TODO())
	if err != nil {
		l.logger.Error("Unable to get statsSummary", "error", err.Error())
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	var statsSummaryRes map[string]interface{}
	if err := json.Unmarshal(statsSummary, &statsSummaryRes); err != nil {
		l.logger.Error("error unmarshaling statsSummaryRes response", "error", err.Error())
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	l.logger.Info("Unmarshalled statsSummaryRes", "statsSummary", statsSummaryRes)
	auditLogsSteps := make([]*proto.Step, 0)
	auditLogsSteps = append(auditLogsSteps, &proto.Step{
		Title:       "Fetched statsSummaryRes config",
		Description: "Fetched statsSummaryRes config using internal k8s API.",
	})
	clusterData["statsSummary"] = statsSummaryRes
	activities = append(activities, &proto.Activity{
		Title:       "Finsihed parsing statsSummaryRes",
		Description: "Finished parsing statsSummaryRes",
		Steps:       auditLogsSteps,
	})

	// Acvitity: Eval
	l.logger.Debug("evaluating clusterData data", clusterData)
	for _, policyPath := range request.GetPolicyPaths() {
		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
				Props: nil,
			},
			{
				Title: "Continuous Compliance Framework - K8S cluster Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-kubernetes-cluster",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' K8S Cluster Plugin"),
					},
				},
				Props: nil,
			},
		}

		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/kubernetes-cluster",
			},
		}
		subjectAttributeMap := map[string]string{
			"type":         "k8s-native-cluster",
			"cluster_info": fmt.Sprintf("%v", clusterData),
		}

		subjects := []*proto.SubjectReference{
			{
				Type:       "cluster",
				Attributes: subjectAttributeMap,
				Title:      internal.StringAddressed("Cluster Instance"),
				Remarks:    internal.StringAddressed("A k8s deployment running checks against cluster configuration"),
				Props: []*proto.Property{
					{
						Name:    "cluster",
						Value:   "CCF",
						Remarks: internal.StringAddressed("The cluster of which the policy was executed against"),
					},
				},
			},
		}

		results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", clusterData)
		policyBundleSteps := make([]*proto.Step, 0)
		policyBundleSteps = append(policyBundleSteps, &proto.Step{
			Title:       "Compile policy bundle",
			Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
		})
		policyBundleSteps = append(policyBundleSteps, &proto.Step{
			Title:       "Execute policy bundle",
			Description: "Using previously collected JSON-formatted K8S configurations, execute the compiled policies",
		})
		activities = append(activities, &proto.Activity{
			Title:       "Execute policy",
			Description: "Prepare and compile policy bundles, and execute them using the prepared K8S configuration data",
			Steps:       policyBundleSteps,
		})
		l.logger.Debug("local kubernetes K8S policy runs completed", "results", results)

		activities = append(activities, &proto.Activity{
			Title:       "Compile Results",
			Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
			Steps:       policyBundleSteps,
		})

		if err != nil {
			l.logger.Error("policy evaluation for K8S failed", "error", err)
			errAcc = errors.Join(errAcc, err)
			return observations, findings, errAcc
		}

		for _, result := range results {
			observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "observation",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			observationUUID, err := sdk.SeededUUID(observationUUIDMap)
			if err != nil {
				errAcc = errors.Join(errAcc, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "finding",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			findingUUID, err := sdk.SeededUUID(findingUUIDMap)
			if err != nil {
				errAcc = errors.Join(errAcc, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			observation := proto.Observation{
				ID:         uuid.New().String(),
				UUID:       observationUUID.String(),
				Collected:  timestamppb.New(startTime),
				Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
				Origins:    []*proto.Origin{{Actors: actors}},
				Subjects:   subjects,
				Activities: activities,
				Components: components,
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the K8S configuration, using the K8S Native Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}

			newFinding := func() *proto.Finding {
				return &proto.Finding{
					ID:        uuid.New().String(),
					UUID:      findingUUID.String(),
					Collected: timestamppb.New(time.Now()),
					Labels: map[string]string{
						"type":         "k8s-native",
						"host":         "CCF cluster",
						"_policy":      result.Policy.Package.PurePackage(),
						"_policy_path": result.Policy.File,
					},
					Origins:             []*proto.Origin{{Actors: actors}},
					Subjects:            subjects,
					Components:          components,
					RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
					Controls:            nil,
				}
			}

			if len(result.Violations) == 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("K8S Native Validation on %s passed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the K8S Native Compliance Plugin.", result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				finding := newFinding()
				finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
				finding.Description = fmt.Sprintf("No violations found on the %s policy within the K8S Native Compliance Plugin.", result.Policy.Package.PurePackage())
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusSatisfied,
				}
				findings = append(findings, finding)
				continue
			}

			if len(result.Violations) > 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the K8S Native Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				for _, violation := range result.Violations {
					finding := newFinding()
					finding.Title = violation.Title
					finding.Description = violation.Description
					finding.Remarks = internal.StringAddressed(violation.Remarks)
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusNotSatisfied,
					}
					findings = append(findings, finding)
				}
			}
		}

	}

	return observations, findings, errAcc

}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating k8s cluster plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
