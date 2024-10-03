package app.abac

default allow = false

allow {
    input.jwt.claims.role[_] == "customer"
    input.jwt.claims.age >= 18
}
