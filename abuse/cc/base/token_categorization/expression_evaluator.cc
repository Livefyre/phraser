#include "expression_evaluator.h"

ExpressionEvaluator::~ExpressionEvaluator() {
}

bool ExpressionEvaluator::IsExpressionPossible(const Expression& expr) const {
    if (expr.type() != type_) {
        return false;
    }

    for (auto& it : expr.dimension2values()) {
        auto& expr_dimension = it.first;

        auto jt = dimension2possible_values_.find(expr_dimension);
        if (jt == dimension2possible_values_.end()) {
            return false;
        }

        auto& expr_values_set = it.second;
        auto& evaluator_values_set = jt->second;
        for (auto& filter : expr_values_set) {
            if (evaluator_values_set.find(filter) ==
                    evaluator_values_set.end()) {
                return false;
            }
        }
    }

    return AreArgsPossible(expr.args());
}
