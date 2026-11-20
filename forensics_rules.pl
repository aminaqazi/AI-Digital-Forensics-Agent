:- dynamic permitted/2.
:- dynamic log_event/5.

% Clear previous facts before loading new evidence
reset_kb :-
    retractall(permitted(_, _)),
    retractall(log_event(_, _, _, _, _)).

% Rule 1: Unauthorized access if user is not permitted on target
unauthorized_access(User, Target) :-
    log_event(_, User, Target, _, _),
    \+ permitted(User, Target).

% Rule 2: Log tampering detected
log_tampered(User, Target) :-
    log_event(_, User, Target, _, 'TAMPERED_LOG').

% Rule 3: Off-hours exfiltration (EXPORT action at 02:00 AM)
suspicious_exfiltration(User, Target) :-
    log_event('02:00 AM', User, Target, 'EXPORT', _).

% Composite Verdict: Critical breach if all three violation rules fire
critical_breach(User, Target) :-
    unauthorized_access(User, Target),
    log_tampered(User, Target),
    suspicious_exfiltration(User, Target).