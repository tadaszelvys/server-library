<?php

namespace OAuth2\ResourceOwner;

interface ResourceOwnerInterface
{
    /**
     * Get resource owner identifier. The ID is a string that represents the resource owner and is unique to the authorization server.
     *
     * @return string ID of the resource owner
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.2
     */
    public function getPublicId();

    /**
     * @param string $public_id
     */
    public function setPublicId($public_id);

    /**
     * Get resource owner type. The type is a string that represents the type of resource owner (end-user, public client, password client, unregistered client...).
     *
     * @return string Type of the resource owner
     */
    public function getType();

    /**
     * @param string $type
     */
    public function setType($type);
}
