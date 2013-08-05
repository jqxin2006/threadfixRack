package com.denimgroup.threadfix.data.entities;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "DeletedSurfaceLocation")
public class DeletedSurfaceLocation extends AuditableEntity {

	public DeletedSurfaceLocation(SurfaceLocation surfaceLocation) {
		if (surfaceLocation != null) {
			if (surfaceLocation.getFinding() != null){
				setDeletedFindingId(surfaceLocation.getFinding().getId());
			}
			setHost(surfaceLocation.getHost());
			setParameter(surfaceLocation.getParameter());
			setPath(surfaceLocation.getPath());
			setPort(surfaceLocation.getPort());
			setProtocol(surfaceLocation.getProtocol());
			setQuery(surfaceLocation.getQuery());
			setId(surfaceLocation.getId());
		}
	}
	
	private static final long serialVersionUID = -998923457381231213L;

	private Integer findingId;
	
	@Size(max = SurfaceLocation.HOST_LENGTH, message = "{errors.maxlength}")
	private String host;
	
	@Size(max = SurfaceLocation.PARAMETER_LENGTH, message = "{errors.maxlength}")
	private String parameter;

	@Size(max = SurfaceLocation.PATH_LENGTH, message = "{errors.maxlength}")
	private String path;
	
	private int port;
	
	@Size(max = 15, message = "{errors.maxlength}")
	private String protocol;
	
	@Size(max = SurfaceLocation.QUERY_LENGTH, message = "{errors.maxlength}")
	private String query;
	
	@Column
	public Integer getDeletedFindingId() {
		return findingId;
	}
	
	public void setDeletedFindingId(Integer findingId) {
		this.findingId = findingId;
	}

	@Column(length = SurfaceLocation.HOST_LENGTH)
	@JsonIgnore
	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	@Column(length = SurfaceLocation.PARAMETER_LENGTH)
	public String getParameter() {
		return parameter;
	}

	public void setParameter(String parameter) {
		this.parameter = parameter;
	}

	@Column(length = SurfaceLocation.PATH_LENGTH)
	@JsonIgnore
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	@Basic
	@JsonIgnore
	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	@Column(length = 15)
	@JsonIgnore
	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	@Column(length = SurfaceLocation.QUERY_LENGTH)
	@JsonIgnore
	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}
}
