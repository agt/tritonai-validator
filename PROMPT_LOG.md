
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

# Prohibit privilege escalation

This change will pertain only to the validator portion.

For all Containers, initContainers, and ephemeralContainers, ensure that:
* securityContext.allowPrivilegeEscalation is missing or False
* securityContext.privileged is missing or False
* securityContext.capabilities.add is missing, empty, or contains only NET_BIND_SERVICE
* securityContext.procMount is missing, empty, or set to Default

For the Pod-level securityContext, ensure that:
* securityContext.sysctls is missing, or an empty list
	
