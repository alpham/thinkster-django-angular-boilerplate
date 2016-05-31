from rest_framework import serializers
from posts.models import Post
from authentication.serializers import AccountSerializer


class PostSerializer(serializers.ModelSerializer):
    author = AccountSerializer(read_only=True, required=False)

    class Meta:
        model = Post

        fields = ('id', 'author', 'content', 'updated_at', 'created_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def get_validation_exclusions(self, *args, **kwargs):
        exclutions = super(PostSerializer, self).get_validation_exclusions()

        return exclutions + ['author']