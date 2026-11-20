package service

import (
	"math"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func (s *Service) TrafficBudgets() ([]api.TrafficBudgetStatus, error) {
	statuses, err := s.ListSubscriptions()
	if err != nil {
		return nil, err
	}
	eff, _ := s.engine.Effective()
	budgets := make([]api.TrafficBudgetStatus, 0, len(statuses))
	now := time.Now().UTC()
	for _, status := range statuses {
		budgets = append(budgets, trafficBudget(status, budgetFor(eff, status.SourceID), now))
	}
	return budgets, nil
}

func budgetFor(eff *compile.Effective, source string) compile.TrafficBudget {
	if eff != nil {
		if budget, ok := eff.TrafficBudgets[source]; ok {
			return budget
		}
	}
	return compile.TrafficBudget{WarnPercent: compile.DefaultBudgetWarning}
}

func trafficBudget(status SubscriptionStatus, budget compile.TrafficBudget, now time.Time) api.TrafficBudgetStatus {
	result := api.TrafficBudgetStatus{SourceID: status.SourceID, State: "unknown", Stale: status.Stale || status.State == "paused",
		ReserveBytes: budget.Reserve, WarnPercent: budget.WarnPercent}
	end := budget.ResetAt
	if !end.IsZero() {
		result.EndReason = "reset"
	}
	usage := status.Usage
	if usage != nil {
		result.ObservedAt = usage.ObservedAt
		result.TotalBytes = usage.Total
		if usage.ExpireUnix != nil && *usage.ExpireUnix > 0 {
			expires := time.Unix(int64(*usage.ExpireUnix), 0).UTC()
			if end.IsZero() || !end.Before(expires) {
				end, result.EndReason = expires, "expiry"
			}
			if !now.Before(expires) {
				result.State = "expired"
			}
		}
	}
	if !end.IsZero() {
		result.EndsAt = &end
		days := uint64(0)
		if now.Before(end) {
			days = uint64(max(1, (end.Unix()-now.Unix()+86399)/86400))
		} else if result.State != "expired" {
			result.State = "reset_due"
		}
		result.DaysRemaining = &days
	}
	if usage == nil || usage.Upload == nil || usage.Download == nil {
		return result
	}
	used := uint64(math.MaxUint64)
	if math.MaxUint64-*usage.Upload >= *usage.Download {
		used = *usage.Upload + *usage.Download
	}
	result.UsedBytes = &used
	if usage.Total == nil || *usage.Total == 0 {
		return result
	}
	total := *usage.Total
	remaining := total - min(total, used)
	spendable := remaining - min(remaining, budget.Reserve)
	result.RemainingBytes, result.SpendableBytes = &remaining, &spendable
	if result.DaysRemaining != nil && *result.DaysRemaining > 0 {
		daily := spendable / *result.DaysRemaining
		result.DailyBytes = &daily
	}
	if result.State != "unknown" {
		return result
	}
	percent := uint64(budget.WarnPercent)
	threshold := total/100*percent + total%100*percent/100
	switch {
	case remaining == 0:
		result.State = "exhausted"
	case spendable == 0:
		result.State = "reserve"
	case remaining <= threshold:
		result.State = "low"
	default:
		result.State = "ok"
	}
	return result
}
