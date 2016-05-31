from rest_framework import permissions


class IsAuthorOfPost(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user and obj:
            return obj.author == request.user
        return False
