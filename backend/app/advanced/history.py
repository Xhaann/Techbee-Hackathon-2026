from app.advanced.schema import HistoricalComparison
from app.incidents.service import IncidentService

MAX_SIMILAR = 5


def compare_history(incidents: IncidentService | None, incident_id: str | None) -> HistoricalComparison:
    if incidents is None or incident_id is None:
        return HistoricalComparison(available=False, message="No incident history context was supplied", similar=[],
                                    recurring_site_domains=[], resolution_notes={})
    similar = incidents.find_similar(incident_id, limit=MAX_SIMILAR)
    recurring = sorted(f"{group.site_id}:{group.fault_domain.value}" for group in incidents.recurring_incidents()
                       if incident_id in group.incident_ids)
    notes = {match.incident_id: match.historical_resolution for match in similar if match.historical_resolution}
    message = f"{len(similar)} historical incidents share attributes with this incident" if similar else "No similar historical incidents"
    return HistoricalComparison(available=True, message=message, similar=similar, recurring_site_domains=recurring,
                                resolution_notes=notes)
