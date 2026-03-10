
# This file contains the raw prompts provided to Claude Code 


Write a Kubernetes validating admission webhook service using Python/FastAPI which ensures Pods and their Containers meet per-namespace security requirements.

Kubernetes documentation: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/

Specific security requirements for a pod will be set via annotations on its parent namespace object.  

Each annotation will specify a comma-delimited list of one or more constraints as outlined below.

* Annotation "securityContext/runAsUser":
    * Example values:
        * "1000"
        * "1000,1001"
        * "1000,1001,2000-3000,>5000000"
    * Behavior:
        *  If this constraint is present in the namespace annotations, ensure that all of the following are true:
            *  a Pod-scope securityContext, if present,  specifies a runAsUser matching criteria listed in the annotation; and
            *  all Container and initContainer securityContexts, if present, specify a runAsUser matching criteria listed in the annotation; and
            *  if a Pod-scope securityContext is not present, _all_ Containers and initContainers must supply a securityContext and runAsUser matching the criteria.

* Annotation "securityContext/runAsGroup":
    * Example values:
        * "1000"
        * "1000,1001"
        * "1000,1001,2000-3000,>5000000"
    * Behavior:
        *  Analogous to "runAsUser" above, but for the securityContext's runAsGroup field

* Annotation "securityContext/fsGroup":
    * Example values:
        * "1000"
        * "1000,1001"
        * "1000,1001,2000-3000,>5000000"
    * Behavior:
        *  Analogous to "runAsUser" above, but for the securityContext's fsGroup field
        *  This constraint is satisfied if no fsGroup value is present in either the Pod or any of its Containers/initContainers.

* Annotation "securityContext/supplementalGroups":
    * Example values:
        * "1000"
        * "1000,1001"
        * "1000,1001,2000-3000,>5000000"
    * Behavior:
        *  Analogous to "runAsUser" above, but for each entry in the (optional) list of supplementalGroups
        *  This constraint is satisfied if no supplementalGroups list is present in either the Pod or any of its Containers/initContainers.

* Annotation "securityContext/allowPrivilegeEscalation"
    * Permitted values:
        * "true"
        * "false"
    * Behavior:
        * If this constraint is present in the namespace annotations, ensure that all of the following are true:
            *  a Pod-scope securityContext, if present,  specifies an allowPrivilegeEscalation value matching the annotation; and
            *  all Container and initContainer securityContexts, if present, specify an allowPrivilegeEscalation value matching the annotation; and
            *  if a Pod-scope securityContext is not present, _all_ Containers and initContainers must supply a securityContext and allowPrivilegeEscalation value matching the criteria.

            
Code should permit addition of new constraints in the future, including an allowance for future non-numeric string criteria (e.g. shell globs).

# Annotation prefix change

please change the annotation prefix from "securityContext" to "sc.dsmlp.ucsd.edu", e.g. "sc.dsmlp.ucsd.edu/runAsUser"

# NodeLabel

add support for a new constraint annotation "sc.dsmlp.ucsd.edu/nodeLabel"
with example values "partition=a", "rack=b,rack=c".  If this attribute
is present,  the pod specification must include a nodeSelector
statement matching one of the attribute values.  (Other nodeSelector
rules may be present as long as at least one of them matches the
annotation constraint.). furthermore, if a "sc.dsmlp.ucsd.edu/nodeLabel"
annotation is present in the namespace, ensure that podSpecs do not
bypass this constraint by specifying "nodeName" - this field must
be absent.

# Readme

Please update README.md to reflect the new nodeLabel behavior.


# Mutator

Now, adapt this code to make a Mutating Admission Controller following the same approach.

A new set of Namespace attributes will be introduced, each providing defaults the corresponding validating criteria.

For example, a missing or nonconforming "runAsUser" should be replaced with the value within "sc.dsmlp.ucsd.edu/default.runAsUser".

First, adjust any Container/initContainer securityContext sections present so that their values meet the criteria.

Next, adjust the Pod-level securityContext so that its values meet the criteria. If one or more containers is missing a securityContext section, and there is no Pod-level section, create a new one for the Pod.

If the namespace lacks a required default annotation, generate a log message to this effect, but proceed with remediation of other criteria.

Similarly, if a provided default value does not meet the validation criteria, generate a log message and proceed as if it were absent.

Following mutation, the API server will send the resulting pod through the Validating Webhook which will block any deficient pods.

# Back out allowPrivilegeEscalation

remove support for  "allowPrivilegeEscalation" constraints - we will address it in a future update.

# Also check ephemeralContainers

Update checks to include a pod's ephemeralContainers in addition to initContainers and Containers.

# Hardcoded security standards

This change will pertain only to the validator portion.

For all Containers, initContainers, and ephemeralContainers, ensure that:
* securityContext.allowPrivilegeEscalation is missing or False
* securityContext.privileged is missing or False
* securityContext.capabilities.add is missing, empty, or contains only NET_BIND_SERVICE
* securityContext.procMount is missing, empty, or set to Default

For the Pod-level securityContext, ensure that:
* securityContext.sysctls is missing, or an empty list
	

# Remove validation from the Mutator

Remove all constraint checks from the mutator, so that its only job is to apply defaults when the relevant fields are empty.

# Volume constraints

a) Add a new hardcoded Validator constraint ensuring that Pod volumes are only of the following types: "configMap,downwardAPI, emptyDir,image,nfs,persistentVolumeClaim,secret,
serviceAccountToken,clusterTrustBundle,podCertificate".

b) Add a new Validator namespace attribute constraint "sc.dsmlp.ucsd.edu/allowedNfsVolumes" which defines which (server, remote path) pairs are permitted within a Pod specification's NFS volumes, if any are present.

There is no default, a missing attribute should be processed as if it were an empty string.

The constraint attribute value is a comma-separated list of NFS remote resource names, each following the Linux mount convention of "servername:/path/to/mount". For example: "10.20.5.3:/export/data,itsnfs:/scratch,its-dsmlp-fs03:/export/workspaces/PROJ_TEST".

Each of the Pod's NFS Volumes, if any, must match at least one of the remote resources listed in the constraint attribute.

A match is defined either as a direct string match (server to server, path to path), or by treating the constraint resource name as a shell glob, e.g. "its-dsmlp-fs0[1-9]:/export/workspaces/*FA25", and that shell glob pattern matching the Pod Volume.

# Scope of nodeSelector

The mutator should only insert default.nodeSelector if the pod fails to specify any nodeSelector.

# Extend list of permitted volume types

add "projected" to the list of allowed volume types.

# Permit narrowing of the allowed volume types (e.g. disallow secrets, configmaps, 

Add a new optional constraint "sc.dsmlp.ucsd.edu/prohibitedVolumeTypes" which removes one or more volume types from the hardcoded initial set of permitted volume types.

# Protect non-Volume access to data sources

Some data sources may be presented either via Volumes or as environment variables through Env or EnvFrom. When a volume type is prohibited, we will also block the corresponding environment variable path.

If "configMap" is prohibited by way of the "prohibitedVolumeTypes" annotation, reject attempts to include configMapKeyRef or configMapRef in Env/EnvFrom or downwardAPI sections.

If "secret" is prohibited by way of the "prohibitedVolumeTypes" annotation, reject attempts to include secretKeyRef or secretRef in Env/EnvFrom sections.

If "downwardAPI" is prohibited by way of the "prohibitedVolumeTypes" annotation, reject attempts to include fieldRef or resourceFieldRef in Env/EnvFrom sections.

Generate code to implement the above, and update README.md to document the additional behavior.

# Workload template validation

Expand scope of the validator to include review of of the Pod templates contained within Deployment, Job, CronJob, StatefulSet, and similar kubernetes objects. Pass the template through the mutator code first to ensure defaults are applied, then validate the updated template as you would a Pod against namespace-specific and hardcoded constraints.

# Restrict mutator to Pod only

When called by the kubernetes API server, the mutator should only patch kind==Pod.  (mutator may be called internally to support validation of workload templates).

# Update prompt log

please update PROMPT_LOG.md to incorporate any of my prompts which have not been captured there.

# Host namespace hardcoded rules

Update the Validator hardcoded rules to enforce that Pod spec.hostNetwork, spec.hostPID, spec.hostIPC are each either absent, or set to False;  no changes to mutator are needed.

# runAsNonRoot REQUIRED_SCALAR constraint

update Validator to enforce a new REQUIRED_SCALAR constraint "runAsNonRoot" which must be True following the same semantics as runAsUser:  if defined in any container, it must be set to "True"; and unless all containers set runAsNonRoot to true, the Pod security context must do so.

# runAsNonRoot mutator default

update Mutator to set pod securityContext.runAsNonRoot=True if that field is empty or absent.

# Update README and prompt log

Update README.md's documentation and its Pod Security Standard comparison matrix to reflect recent changes.  Also update PROMPT_LOG.md to include any meaningful prompts not already there.

# Default toleration injection (mutator)

Add to the Mutator a new optional `sc.dsmlp.ucsd.edu/default.tolerations` namespace annotation which can contain a comma-separated list of Tolerations to be applied to the Pod spec. Defaults should be imposed only if the pod's toleration field is absent or empty.

Each default toleration should be of the format "key=value:effect". If the "value" is the special value "*", the generated Toleration should use the "Exists" operator, otherwise "Equal".

# Toleration allowlist (validator)

Add to the Validator a new constraint `sc.dsmlp.ucsd.edu/tolerations` namespace annotation which, if present, is a comma-delimited list of permissible Tolerations.

Each permitted-toleration entry should be of the format "key=value:effect".

The Validator should compare all Tolerations in the pod spec against the permitted list. The permitted-toleration entries may utilize shell globs (fnmatch style) in any field.

As a special case, a value of "*" should match any Pod spec value ("Equal" operator) as well as the value-less "Exists" operator. For example: `"sc.dsmlp.ucsd.edu/tolerations": "node-type=*:NoSchedule"` should permit a toleration with `operator: Exists` and `effect: NoSchedule`.

# Supplemental groups list default

The mutator should accept a list of default supplemental group IDs e.g. '1000,2022,3900' in addition to a single scalar.

# Helm chart and deployment restructure

Move the current deploy/*.yaml files into a new directory deploy/standalone/*.yaml; then within a new directory deploy/helm/, create a helm chart structure with templates based on the standalone yaml files. Ensure configuration points (e.g. kubernetes object names) are defined within a values.yaml file referenced by the generated templates.

# Exempt node.kubernetes.io/* tolerations

Update toleration handling to ignore 'node.kubernetes.io/*' Tolerations when deciding whether to inject defaults: if node.kubernetes.io/* are the only tolerations present, add in default.tolerations. Similarly, always allow 'node.kubernetes.io/*' tolerations within the Validator, even if they aren't specifically listed in the corresponding namespace annotation.

# hostPort constraint

Add a new hard-coded Validator constraint: no container's `ports` section may specify a 'hostPort' value. Update code, tests, and README.md to reflect the change.

# Configurable annotation prefix and policy. marker

Rebase code from upstream, then implement two changes:
1) Change the constant annotation prefix 'sc.dsmlp.ucsd.edu' into one changeable via an environment variable ANNOTATION_PREFIX; default value if this variable is not set: 'tritonai-admission-webhook'.
2) Prepend a marker 'policy.' to validator constraint annotations, e.g. 'tritonai-admission-webhook/policy.runAsUser'; this parallels use of 'default.' for the mutator defaults.
Propagate this change to code as well as README.md and deployment artifacts.

# Shared pod helper refactor

Extract duplicated container/securityContext helper functions (_pod_sc, _all_containers, _container_sc, _container_name, _is_node_kubernetes_toleration) into a shared app/pod_helpers.py module imported by both the mutator and validator. Remove the redundant _CONTAINER_KINDS constant from the mutator and simplify _any_container_missing_field to use _all_containers().
