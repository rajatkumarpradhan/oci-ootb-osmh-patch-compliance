# OS Management Hub read wiring for the compliance workflow (template; NOT applied).
#
# OS Management Hub (OSMH) is the out-of-the-box OCI feature that inventories
# managed instances and their pending updates. This template reads the
# managed instances in a compartment as a data source; the local reporter in
# src/ turns an export of that state into a compliance report with a security
# patch window.
#
# This file has NOT been plan/apply validated against a tenancy - it is a
# structural template. Review against the current provider docs before any
# real apply.

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

variable "compartment_ocid" {
  type        = string
  description = "OCID of the compartment whose managed instances to read"
}

data "oci_os_management_hub_managed_instances" "fleet" {
  compartment_id = var.compartment_ocid
}

output "managed_instance_names" {
  value = [for i in data.oci_os_management_hub_managed_instances.fleet.managed_instance_collection[0].items : i.display_name]
}
