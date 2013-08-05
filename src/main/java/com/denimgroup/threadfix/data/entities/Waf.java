////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "Waf")
public class Waf extends AuditableEntity {

	private static final long serialVersionUID = 2937339816996157154L;

	public static final int NAME_LENGTH = 50;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;
	private WafType wafType;
	private Integer currentId;
	private WafRuleDirective lastWafRuleDirective;

	private List<Application> applicationList;
	private List<WafRule> wafRuleList;
	
	boolean canDelete = false;

	@Column(length = NAME_LENGTH, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	@Column
	public Integer getCurrentId() {
		return currentId;
	}

	public void setCurrentId(Integer currentId) {
		this.currentId = currentId;
	}

	@ManyToOne
	@JoinColumn(name = "wafTypeId")
	public WafType getWafType() {
		return wafType;
	}

	public void setWafType(WafType wafType) {
		this.wafType = wafType;
	}
	
	@ManyToOne
	@JoinColumn(name = "wafRuleDirectiveId")
	public WafRuleDirective getLastWafRuleDirective() {
		return lastWafRuleDirective;
	}

	public void setLastWafRuleDirective(WafRuleDirective lastWafRuleDirective) {
		this.lastWafRuleDirective = lastWafRuleDirective;
	}

	@OneToMany(mappedBy = "waf")
	@JsonIgnore
	public List<Application> getApplications() {
		return applicationList;
	}

	public void setApplications(List<Application> applicationList) {
		this.applicationList = applicationList;
	}

	@OneToMany(mappedBy = "waf")
	public List<WafRule> getWafRules() {
		return wafRuleList;
	}

	public void setWafRules(List<WafRule> wafRuleList) {
		this.wafRuleList = wafRuleList;
	}
	
	@Transient
	public boolean getCanDelete() {
		boolean hasActiveApplication = false;
		if (getApplications() != null) {
			for (Application application : getApplications()) {
				if (application.isActive()) {
					hasActiveApplication = true;
					break;
				}
			}
		}
		return !hasActiveApplication;
	}

}
