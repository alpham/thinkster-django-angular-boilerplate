from rest_framework import permissions


class IsAccountOwner(permissions.BasePermission):
    def get_object_permission(self, request, view, account):
        if request.user:
            return account == request.user
        return False

